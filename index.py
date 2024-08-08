import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import bcrypt
import re
import string
import secrets
import pyperclip
import sqlite3

#database setup
conn = sqlite3.connect('password_manager.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS passwords
            (id INTEGER PRIMARY KEY AUTOINCREMENT,
          website TEXT,
          username TEXT,
          password TEXT)''')
conn.commit()

#Master password setup
master_password = b'0xSpecial0ne.m3' # replace with your master password
hashed_master_password = bcrypt.hashpw(master_password, bcrypt.gensalt())

#Root window
root = tk.Tk() # the main application window
root.title('Password Manager') # The title of the application window
root.withdraw()

#styling
s = ttk.Style() #create a style object
s.theme_use('clam') # set the theme of the style to clam
s.configure('Tframe', background='grey') # configure the Tframe style with a grey background

#Frame layout
frame = ttk.Frame(root) #Create a frame to hold the widget
frame.pack(expand=True, fill='both', padx=40, pady=20) # pack the frame to fill the entire window

# Define the large font
LARGE_FONT = ('Times New Roman', 18) # define the font style for the the title label

#Title
title = ttk.Label(frame, text='Janelle Password manager', font=(LARGE_FONT[0], LARGE_FONT[1], 'bold')) # create a label title

#fields
website_label = ttk.Label(frame, text='website:') # Label for the website field
username_label = ttk.Label(frame, text='Username:') # label for username field
password_label = ttk.Label(frame, text='Password:') #Label ffor the password field

website_entry = ttk.Entry(frame) #Entry widget for the website
username_entry = ttk.Entry(frame) # Entry widget for the username
password_entry = ttk.Entry(frame, show='*') #Entry widget for the password (with mask)

#Password strength meter
strength_meter = ttk.Progressbar(frame, orient='horizontal', length=200, mode='determinate')# Progressbar for password strength

#function to toggle password visibility
def toggle_password_visibility():
    if password_entry['show'] == '*':
        password_entry['show'] = '' #Show the password in plain text
    else:
        password_entry['show'] = '*' #Mask the password

#Generate password function
def generate_password():
    #Generate a random password with letters, digits and special characters
    password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(15))
    password_entry.delete(0, tk.END) #clear any existing text in the password entry
    password_entry.insert(0, password) # Insert the generate password into the password entry
    check_strength()

generate_btn = ttk.Button(frame, text='Generate Password', command=generate_password) # Button to generate a password

#function to check and calculate password strength
def check_strength():
    password = password_entry.get() #Get the password fro the password entry
    #Calculate strength based on various criteria
    strength = 0
    if len(password) >= 15:
        strength += 1
    if re.search("[a-z]", password):
        strength += 1
    if re.search("[A-Z]", password):
        strength += 1
    if re.search("[0-9]", password):
        strength += 1
    #Upate the strength meter
    strength_meter['maximum'] = 10
    strength_meter['value'] = strength

strength_meter.grid(row=3, column=2, pady=10, padx=10) #Place the strength meter in the frame

#Database functions
def save_password():
    website = website_entry.get()# Get the website from the entry
    username = username_entry.get()# Get the username from the entry
    password = password_entry.get()#get the password from the entry
    c.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)', (website, username, password))
    conn.commit() #Commit changes to the database
    update_password_listbox() #Update the password listbox with saved password
    # Display a message a message box when the password is saved
    messagebox.showinfo('Success', 'Password saved!')

# Function to search for a password in the database
def search_password():
    #Define a function to create a search popup
    def search_popup():
        #create a new popup window
        popup = tk.Toplevel()
        popup.title('Search Password')
        popup.geometry('300x100')
        popup.resizable(False, False)

        #Create a label prompting the user to enter a website or username
        search_label = ttk.Label(popup, text='Enter website or username')
        search_label.pack(pady=10)
        #Create an entry field for the user to input their search
        search_entry = ttk.Entry(popup)
        search_entry.pack(pady=5)
        #Define a function to perform the search
        def search():
            search_value = search_entry.get()

            #Execute an SQL query to search for the entered valuse in the database
            c.execute('SELECT * FROM passwords WHERE website=?', (search_value, search_value))
            result = c.fetchone() # Fetch the first result
            if result:
                #If a reult is found, extract the website, username and password
                website, username, password = result[1], result[2], result[3]

                #Clear any existing data and insert the retrieved data into entry fields
                website_entry.delete(0, tk.END)
                username_entry.delete(0, tk.END)
                password_entry.delete(0, tk.END)
                website_entry.insert(0, website)
                username_entry.insert(0, username)
                password_entry.insert(0, password)
                #close the popup window
                popup.destroy()
            else:
                #Display a message box if the password is not found
                messagebox.showinfo('Search Result', 'Password not found for the specified website or username.')
          #Create a search button that calls the search function when clicked
        search_button = ttk.Button(popup, text='search', command=search)
        search_button.pack(pady=5)
      #Call the search_popup function to display the search popup
    search_popup()

#Password listbox to view saved password
password_listbox = tk.Listbox(frame)
password_listbox.grid(row=7, column=0, columnspan=3, pady=10, padx=10)

#Function to update a password in the database
def update_password():
    def update_popup():
        popup = tk.Toplevel()
        popup.title('Update Password')
        popup.geometry('300x150')
        popup.resizable(False, False)

        update_label = ttk.Label(popup, text='Enter website or username to update password:')
        update_label.pack(pady=10)

        update_entry = ttk.Entry(popup)
        update_entry.pack(pady=5)

        def update():
            update_value = update_entry.get()
            c.execute('SELECT * FROM passwords WHERE website=? OR username=?', (update_value, update_value))
            result = c.fetchone()
            if result:
                website, username, password = result[1], result[2], result[3]
                website_entry.delete(0, tk.END)
                username_entry.delete(0, tk.END)
                password_entry.delete(0, tk.END)
                website_entry.insert(0, website)
                username_entry.insert(0, username)
                password_entry.insert(0, password)
                popup.destroy()
            else:
                # Display a message box if the password is not found
                messagebox.showinfo('Update Result', 'No matcing record for the specific website or Username.')
        update_button = ttk.Button(popup, text='Update', command=update)
        update_button.pack(pady=5)
    update_popup()

#Function to update the password listbox with saved passwords
def update_password_listbox():
    password_listbox.delete(0, tk.END) # clear the current list
    c.execute('SELECT website FROM passwords')
    websites = c.fetchall()
    for website in websites:
        password_listbox.insert(tk.END, website[0])
update_password_listbox()

#Function to delete a password from the database
def delete_password():
    def delete_pop():
        popup = tk.Toplevel()
        popup.title('Delete Password')
        popup.geometry('300x50')
        popup.resizable(False, False)

        delete_label = ttk.Label(popup, text='Enter website or username to delete password:')
        delete_label.pack(pady=10)

        delete_entry = ttk.Entry(popup)
        delete_entry.pack(pady=5)

        def delete():
            delete_value = delete_entry.get()
            c.execute('SELECT * FROM paswords WHERE website=? OR username=?', (delete_value, delete_value))
            result = c.fetchone()
            if result:
                website, username, password = result[1], result[2], result[3]
                choice = messagebox.askquestion('Delete confirmation', f'Are you sure you want to delete the password for {website}?')
                if choice == 'yes':
                    c.execute('DELETE FROM passwords WHERE websites=?', (website,))
                    conn.commit()
                    update_password_listbox()
                    popup.destroy()
                    # Display a message box when the password is deleted
                    messagebox.showinfo('Success', 'Password deleted!')
                else:
                    # Display a message box when the password is not found
                    messagebox.showinfo('Delete Result', 'No matching record found for the specified website or username.')
            delete_button =ttk.Button(popup, text='Delete', command=delete)
            delete_button.pack(pady=5)

        delete_pop()

#Function to copy the password to the clipboard
def copy_password():
    pyperclip.copy(password_entry.get())

# Buttons for various operations
save_btn = ttk.Button(frame, text='Save Password', command=save_password)
search_btn = ttk.Button(frame, text='Search Password', command=search_password)
update_btn = ttk.Button(frame, text='Update Password', command=update_password)
delete_btn = ttk.Button(frame, text='Delete Password', command=delete_password)
copy_btn = ttk.Button(frame, text='Copy Password', command=copy_password)

#Add an eye icon button to toggle password visibility
toggle_visibility_btn = ttk.Button(frame, text='0', command=toggle_password_visibility)

#Global variable to track incorrect attempts
incorrect_attempts = 0

#Function to verify the master password
def verify_master_password():
    global incorrect_attempts # Declare that we are using the global incorrect variable
    input_password = master_password_entry.get().encode('utf-8') # Get the entered password and encodes it
    if bcrypt.checkpw(input_password, hashed_master_password): #check if the entered password matches the hashed master pasword
        master_password_frame.destroy() # close the master password entry window
        root.deiconify() #show the main application window
    else:
        incorrect_attempts += 1 # Increment the incorrect_attempts counter
        if incorrect_attempts >= 3: #if incorrect_attempts reaches 3 or more
          messagebox.showerror('Maximum Attempts Exceeded', 'Incorrect password entered thtree times. The application will crash now.')
          root.destroy() #Crash the application
        else:
            messagebox.showerror('Invalid Master Password', 'The entered master password is incorrect.')

# Create a master password entry window
master_password_frame = tk.Toplevel(root)
master_password_frame.title('Master Password')
master_password_label = ttk.Label(master_password_frame, text='Enter Master Password:')
master_password_label.pack()
master_password_entry = ttk.Entry(master_password_frame, show='*')
master_password_entry.pack()
verify_button = ttk.Button(master_password_frame, text='Verify', command=verify_master_password)
verify_button.pack()

#Layout of the widgets in the frame using grid
title.grid(row=0, column=0, columnspan=3, pady=10, padx=10)

website_label.grid(row=1, column=0, pady=10, padx=10, sticky='e')
username_label.grid(row=1, column=0, pady=10, padx=10, sticky='e')
password_label.grid(row=1, column=0, pady=10, padx=10, sticky='e')

website_entry.grid(row=1, column=1, pady=10, padx=10, sticky='w')
username_entry.grid(row=2, column=1, pady=10, padx=10, sticky='w')
password_entry.grid(row=3, column=1, pady=10, padx=10, sticky='w')

generate_btn.grid(row=4, column=0, pady=10, padx=10)
copy_btn.grid(row=4, column=1, pady=10, padx=10)
toggle_visibility_btn.grid(row=4, column=2, pady=10, padx=10)
save_btn.grid(row=5, column=0, pady=10, padx=10)
search_btn.grid(row=5, column=1, pady=10, padx=10)
update_btn.grid(row=6, column=0, pady=10, padx=10)
delete_btn.grid(row=6, column=1, pady=10, padx=10)

root.mainloop()


