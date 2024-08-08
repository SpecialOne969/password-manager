import bcrypt
import re
import string
import secrets
import pyperclip
import sqlite3
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.progressbar import ProgressBar

# Database setup
conn = sqlite3.connect('password_manager.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS passwords
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
             website TEXT,
             username TEXT,
             password TEXT)''')
conn.commit()

# Master password setup
master_password = b'0xSpecial0ne.m3'  # Replace with your master password
hashed_master_password = bcrypt.hashpw(master_password, bcrypt.gensalt())

class PasswordManagerApp(App):

    def build(self):
        self.incorrect_attempts = 0
        return self.master_password_screen()

    def master_password_screen(self):
        layout = BoxLayout(orientation='vertical', padding=10)
        self.master_password_input = TextInput(password=True, multiline=False)
        verify_button = Button(text='Verify', on_press=self.verify_master_password)
        layout.add_widget(Label(text='Enter Master Password:'))
        layout.add_widget(self.master_password_input)
        layout.add_widget(verify_button)
        return layout

    def main_screen(self):
        layout = BoxLayout(orientation='vertical', padding=10)
        grid = GridLayout(cols=2, spacing=10, size_hint_y=None)
        grid.bind(minimum_height=grid.setter('height'))

        self.website_input = TextInput(multiline=False)
        self.username_input = TextInput(multiline=False)
        self.password_input = TextInput(password=True, multiline=False)
        self.strength_meter = ProgressBar(max=10)

        generate_btn = Button(text='Generate Password', on_press=self.generate_password)
        copy_btn = Button(text='Copy Password', on_press=self.copy_password)
        save_btn = Button(text='Save Password', on_press=self.save_password)
        search_btn = Button(text='Search Password', on_press=self.search_password)
        update_btn = Button(text='Update Password', on_press=self.update_password)
        delete_btn = Button(text='Delete Password', on_press=self.delete_password)
        toggle_visibility_btn = Button(text='Show/Hide Password', on_press=self.toggle_password_visibility)

        grid.add_widget(Label(text='Website:'))
        grid.add_widget(self.website_input)
        grid.add_widget(Label(text='Username:'))
        grid.add_widget(self.username_input)
        grid.add_widget(Label(text='Password:'))
        grid.add_widget(self.password_input)
        grid.add_widget(Label(text='Strength:'))
        grid.add_widget(self.strength_meter)
        grid.add_widget(generate_btn)
        grid.add_widget(copy_btn)
        grid.add_widget(save_btn)
        grid.add_widget(search_btn)
        grid.add_widget(update_btn)
        grid.add_widget(delete_btn)
        grid.add_widget(toggle_visibility_btn)

        layout.add_widget(grid)
        return layout

    def verify_master_password(self, instance):
        input_password = self.master_password_input.text.encode('utf-8')
        if bcrypt.checkpw(input_password, hashed_master_password):
            self.root.clear_widgets()
            self.root.add_widget(self.main_screen())
        else:
            self.incorrect_attempts += 1
            if self.incorrect_attempts >= 3:
                App.get_running_app().stop()
            else:
                popup = Popup(title='Invalid Master Password',
                              content=Label(text='The entered master password is incorrect.'),
                              size_hint=(0.8, 0.2))
                popup.open()

    def generate_password(self, instance):
        password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(15))
        self.password_input.text = password
        self.check_strength()

    def check_strength(self):
        password = self.password_input.text
        strength = 0
        if len(password) >= 15:
            strength += 1
        if re.search("[a-z]", password):
            strength += 1
        if re.search("[A-Z]", password):
            strength += 1
        if re.search("[0-9]", password):
            strength += 1
        self.strength_meter.value = strength

    def save_password(self, instance):
        website = self.website_input.text
        username = self.username_input.text
        password = self.password_input.text
        c.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)', (website, username, password))
        conn.commit()
        self.show_popup('Success', 'Password saved!')

    def search_password(self, instance):
        self.search_popup('Search Password', self.perform_search)

    def perform_search(self, search_value):
        c.execute('SELECT * FROM passwords WHERE website=? OR username=?', (search_value, search_value))
        result = c.fetchone()
        if result:
            website, username, password = result[1], result[2], result[3]
            self.website_input.text = website
            self.username_input.text = username
            self.password_input.text = password
        else:
            self.show_popup('Search Result', 'Password not found for the specified website or username.')

    def update_password(self, instance):
        self.search_popup('Update Password', self.perform_update)

    def perform_update(self, update_value):
        c.execute('SELECT * FROM passwords WHERE website=? OR username=?', (update_value, update_value))
        result = c.fetchone()
        if result:
            website, username, password = result[1], result[2], result[3]
            self.website_input.text = website
            self.username_input.text = username
            self.password_input.text = password
        else:
            self.show_popup('Update Result', 'No matching record for the specified website or username.')

    def delete_password(self, instance):
        self.search_popup('Delete Password', self.perform_delete)

    def perform_delete(self, delete_value):
        c.execute('SELECT * FROM passwords WHERE website=? OR username=?', (delete_value, delete_value))
        result = c.fetchone()
        if result:
            website = result[1]
            c.execute('DELETE FROM passwords WHERE website=?', (website,))
            conn.commit()
            self.show_popup('Success', 'Password deleted!')
        else:
            self.show_popup('Delete Result', 'No matching record for the specified website or username.')

    def copy_password(self, instance):
        pyperclip.copy(self.password_input.text)

    def toggle_password_visibility(self, instance):
        if self.password_input.password:
            self.password_input.password = False
        else:
            self.password_input.password = True

    def search_popup(self, title, search_function):
        layout = BoxLayout(orientation='vertical', padding=10)
        search_input = TextInput(multiline=False)
        search_button = Button(text='Search', on_press=lambda x: search_function(search_input.text))
        layout.add_widget(Label(text='Enter website or username:'))
        layout.add_widget(search_input)
        layout.add_widget(search_button)
        popup = Popup(title=title, content=layout, size_hint=(0.8, 0.4))
        popup.open()

    def show_popup(self, title, message):
        popup = Popup(title=title, content=Label(text=message), size_hint=(0.8, 0.4))
        popup.open()

if __name__ == '__main__':
    PasswordManagerApp().run()
