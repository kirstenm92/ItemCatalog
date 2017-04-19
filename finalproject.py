from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
# I couldn't make the above line <80 characters without an error :(
from functools import wraps
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

# Authorisation additions
from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers2.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


"""Authorisation connects"""


# Google connect
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    # result = json.loads(h.request(url, 'GET')[1]) added below from Steve
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    # someone else's solution
    # gplus_id = credentials['id_token']['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already'
        ' connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['credentials'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # Add provider to login session
    login_session['provider'] = 'google'

    # See if user exists, if it doesn't, make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: '
    '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# Facebook connect
@app.route('/fbconnect', methods =['POST'])
def fbconnect():

    # Short-lived token
    # Verify value of state to prevent cross-site forgery attacks
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s" % access_token

    # Exchange client-token for long-lived server-side token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_'
    'exchange_token&'
    'client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    # If token works, can make API calls and populate login session
    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, 
    # let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture (FB uses separate API call to retrieve profile pic)
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect='
    '0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    # Populate login session
    login_session['picture'] = data["data"]["url"]

    # see if user exists
    # exact same code from google login :) - retrieve/create user
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


"""Authorisation disconnects"""


# GOOGLE disconnect 
@app.route("/gdisconnect")
def gdisconnect():
    # Only disconnect a connected user
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected'),
         401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Execute HTTP GET request to revoke current token. (# or access_token)
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials  
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# FACEBOOK disconnect
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Disconnect function - based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']

        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showRestaurants'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showRestaurants'))


"""Users"""


# Create user
def createUser(login_session):
    newUser = User(name=login_session['username'], email=
        login_session['email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()

    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# If user ID given, returns user object w/ info
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


# Return ID of a user when email provided
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception:  # Steve says add Exception? (mine just except)
        return None


# Created a fx to ensure a user is logged in before proceeding
# Will be used in routing below (to avoid repeating code)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' in login_session:
            return f(*args, **kwargs)
        else:
            flash("You are not allowed to do this! Please login")
            return redirect('/login')
    return decorated_function


""" API END-POINTS (GET requests)"""


# JSON for all restaurants
@app.route('/restaurants/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(Restaurants=[r.serialize for r in restaurants])

# JSON for a full menu for a specific restaurant
@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def menuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=
        restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


# JSON for a specific menu item
@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    menuItem = session.query(MenuItem).filter_by(id = menu_id).one()
    return jsonify(MenuItem = menuItem.serialize)


""" Routing and CRUD functions"""


# General mainpage fx
@app.route('/')
@app.route('/restaurants')
def showRestaurants():

    restaurants = session.query(Restaurant).all()
    if 'username' not in login_session:
        return render_template('publicRestaurants.html',
            restaurants=restaurants)
    else:
        return render_template('restaurants.html', restaurants=restaurants)


@app.route('/restaurants/new', methods=['GET', 'POST'])
@login_required
def newRestaurant():
    """
    newRestaurant creates a new restaurant instance
    
    Args:
        no direct arguments given - but some retrieved and passed in:
        name: given restaurant name (from form)
        user_id: ID of the user creating the restaurant

    Returns:
        creates the new restaurant with given arguments
        returns to showRestaurants mainpage
        renders page with a flash message confirming successful action
    """

    if request.method == 'POST':
        # newRestaurant = Restaurant(name = request.form['name'], 
        # user_id=login_session.get('user_id')) <-- had this here but error
        
        user_id = getUserID(login_session['email'])
        newRestaurant = Restaurant(name = request.form['name'],
            user_id=user_id)
        session.add(newRestaurant)
        session.commit()
        flash("New Restaurant %s Successfully Created!" %newRestaurant.name)

        return redirect(url_for('showRestaurants'))

    else:
        return render_template('newRestaurant.html')


@app.route('/restaurants/<int:restaurant_id>/edit', methods=['GET', 'POST'])
@login_required
def editRestaurant(restaurant_id):
    """
    editRestaurant edits a given restaurant instance
    
    Args:
        restaurant_id: Unique ID of restaurant to be edited

    Returns:
        edits the given restaurant with given arguments
        returns to showRestaurants mainpage
        renders page with a flash message confirming successful action
    """

    user_id = getUserID(login_session['email'])
    editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    
    if editedRestaurant.user_id != user_id:
        return "<script>function myFunction() {alert('You are not authorized "
        "to edit this restaurant. Please create your own restaurant in order "
        "to edit.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        if request.form['name']:

            editedRestaurant.name = request.form['name']
            # unnecessary?
            session.add(editedRestaurant)
            session.commit()
            print login_session
            flash("Restaurant Successfully Edited!!")
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html',
            restaurant=editedRestaurant)


@app.route('/restaurants/<int:restaurant_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteRestaurant(restaurant_id):
    """
    deleteRestaurant deletes a given restaurant instance
    
    Args:
        restaurant_id: Unique ID of restaurant to be deleted

    Returns:
        deletes the given restaurant with given arguments
        returns to showRestaurants mainpage
        renders page with a flash message confirming successful action
    """
    user_id = getUserID(login_session['email'])
    restaurantToDelete = session.query(Restaurant).filter_by(id=restaurant_id).one()


    if restaurantToDelete.user_id != user_id:
        return "<script>function myFunction() {alert('You are not authorized"
        " to delete this restaurant. Please create your own restaurant in"
        " order to delete.');}</script><body onload='myFunction()''>"

    if request.method == 'POST':
        session.delete(restaurantToDelete)
        session.commit()
        flash("%s Successfully Deleted!!" % restaurantToDelete.name)

        return redirect(url_for('showRestaurants'))
    else:
        return render_template('deleteRestaurant.html',
            restaurant=restaurantToDelete)


# Restaurant specifics
@app.route('/restaurants/<int:restaurant_id>')
@app.route('/restaurants/<int:restaurant_id>/menu')
def showMenu(restaurant_id):
    """
    showMenu displays a menu belonging to a given restaurant instance
    
    Args:
        restaurant_id: Unique ID of restaurant who's menu is to be displayed

    Returns:
        if user is not creator of restaurant: public menu page
        otherwise user is the creator: editable menu page
    """
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id).all()
    creator = getUserInfo(restaurant.user_id)
    # user_id = getUserID(login_session['email']) this code caused errors

    if 'username' not in login_session: # user is not logged in - render public page
        return render_template('publicMenu.html', restaurant=restaurant,
            items=items, creator=creator)
    else:
        return render_template('menu.html', restaurant=restaurant, items=items,
         creator=creator)


@app.route('/restaurants/<int:restaurant_id>/menu/new',
    methods=['GET', 'POST'])
@login_required
def newMenuItem(restaurant_id):
    """
    newMenuItem creates a new restaurant instance
    
    Args:
        restaurant_id: The ID of the restaurant to which the item will belong

    Returns:
        returns to showMenu mainpage
        renders page with a flash message confirming successful action
    """

    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()

    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction() {alert('You are not authorized" \
        " to add menu items to this restaurant. Please create your own" \
        " restaurant in order to add items.');}</script><body " \
        "onload='myFunction()''>"

    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], description=
            request.form['description'], price=request.form['price'],
            course=request.form['course'], restaurant_id=restaurant_id,
            user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash("New Menu Item (%s) Successfully Created!!" % (newItem.name))

        return redirect(url_for('showMenu', restaurant_id=restaurant_id))

    else:
        return render_template('newItem.html', restaurant_id=restaurant_id)


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/edit',
    methods=['GET', 'POST'])
@login_required
def editMenuItem(restaurant_id, menu_id):
    """
    editMenuItem edits a menu item belonging to a specific restaurant
    
    Args:
        restaurant_id: The ID of the restaurant to which the item belongs
        menu_id: The unique ID of the specific menu item

    Returns:
        edits the menu item with provided changes from form
        returns to showMenu mainpage
        renders page with a flash message confirming successful action
    """

    # I think these db calls are necessary before the below checks
    # because we need info from them in order to do so
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()

    if login_session['user_id'] != restaurant.user_id:
        # Could also do a flash message here, just trying something new
        return "<script>function myFunction() {alert('You are not authorized " \
        "to edit menu items to this restaurant. Please create your own " \
        "restaurant in order to edit items.');}</script><body " \
        "onload='myFunction()''>"

    if login_session['user_id'] != editedItem.user_id:
        # Could also do a flash message here, just trying something new
        return "<script>function myFunction() {alert('You are not authorized " \
        "to edit this menu item.');}</script><body " \
        "onload='myFunction()''>"

    # not entirely sure how to combine the above two checks
    # or whether its necessary at all

    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']

        session.add(editedItem)
        session.commit()
        flash("Menu Item Successfully Edited!!")

        return redirect(url_for('showMenu', restaurant_id=restaurant_id))

    else:
        return render_template('editItem.html', restaurant_id=restaurant_id,
            menu_id=menu_id, item=editedItem)


@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/delete',
    methods=['GET', 'POST'])
@login_required
def deleteMenuItem(restaurant_id, menu_id):
    """
    editMenuItem deletes a menu item belonging to a specific restaurant
    
    Args:
        restaurant_id: The ID of the restaurant to which the item belongs
        menu_id: The unique ID of the specific menu item

    Returns:
        deletes the menu item
        returns to showMenu mainpage
        renders page with a flash message confirming successful action
    """
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    
    if login_session['user_id'] != itemToDelete.user_id:
        return "<script>function myFunction() {alert('You are not authorized"
        " to delete menu items to this restaurant. Please create your own"
        " restaurant in order to delete items.');}</script><body "
        "onload='myFunction()''>"

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Menu Item Successfully Deleted!!")

        return redirect(url_for('showMenu', restaurant_id=restaurant_id))

    else:
        return render_template('deleteItem.html', item=itemToDelete)


"""End bit"""


if __name__ == '__main__':
    app.secret_key = "super secret key"
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
