README

------
Project 5: Item Catalog
Udacity Full Stack Web Development Nanodegree
Kirsten Meintjes
March 2017
------
Documents:

root
1) client_secrets.json
2) database_setup.py
3) database_setup.pyc
4) fb_client_secrets.json
5) finalproject.py
6) googleappinfo.txt
7) lotsofmenus.py
8) lotsofmenus2.py
9) README.md
10) restaurantmenu.db
11) restaurantmenuwithusers.db
12) restaurantmenuwithusers2.db

/images
(empty: placeholder for further graphic design)

/static
1) styles.css
2) oldstyles.css

/templates
1) base.html
2) deleteItem.html
3) deleteRestaurant.html
4) editItem.html
5) editRestaurant.html
6) header.html
7) login.html
8) menu.html
9) newItem.html
10) newRestaurant.html
11) publicMenu.html
12) publicRestaurants.html
13) restaurants.html

------

Synopsis

This is the fifth of many projects completed for the Udacity Full Stack Web Development Nanodegree. The brief was to create an application that provides a list of items within a variety of categories, as well as provides a user registration and authentication system. Registered users will have the ability to post, edit, and delete their own items (and be restricted to only viewing restaurants and items that others have created).


Motivation

This project was created as per requirements of completion of the course.


Installation

In order to run this project, one needs to have the files as provided saved to their computer. 
Then they must install the vagrant virtual machine and then run the following prompts
in their command line:
- vagrant up (in the vagrant directory for the project) (only for the first time vagrant is being run for this project)
- vagrant ssh
- cd (change directory to the specific folder in which the project is located)
- then the project can be run by running the following command: python finalproject.py 
- this should set up your local server on port 5000 with the app
- therefore, go to your browser and type in 'localhost:5000' and take it from there!



Tests

The code can be tested by playing around on the site. If any errors arise, the command line will give further details (and obviously the code will therefore fail a specific test)


Contributors

Myself (Kirsten Meintjes)
Udacity


License

N/A

