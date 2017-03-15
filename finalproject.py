from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem

app = Flask(__name__)

from flask import session as login_session
import random, string

# Imports for GConnect step
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"

engine = create_engine('sqlite:///restaurantmenu.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


"""Authentication"""

# State token to prevent request forgery
# Stored in session for later validation
@app.route('/login')
def showLogin():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)
	                for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)

# Google connect route and fx
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
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
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
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['credentials'] = credentials.access_token
    #login_session['credentials'] = credentials <-- in provided code
    #login_session['credentials'] = credentials.to_json() <-- was in another solution
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

	# instructor video has data=json.loads(answer.text)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    

    # NEXT SECTION -- commented out for debugging
    # # Add provider to login session
    # login_session['provider'] = 'google'

    # # See if user exists, if it doesn't, make a new one
    # if not getUserID(login_session['email']):
    #     user_id = createUser(login_session)
    #     login_session['user_id'] = user_id
    #     #newUser = User(name = 'username', email = 'email', picture = 'picture')

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output
    
# GOOGLE disconnect route and fx
@app.route("/gdisconnect")
def gdisconnect():
    # Only disconnect a connect user
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    
    # access_token = credentials.access_token <-- if included, error: AttributeError: 'str' object has no attribute 'access_token'

	# Execute HTTP GET request to revoke current token.
	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials   # access_token
	h = httplib2.Http()
	result = h.request(url, 'GET')[0]

	if result['status'] == '200':
	    # Reset the user's session.
	    del login_session['credentials']
	    del login_session['gplus_id']
	    del login_session['username']
	    del login_session['email']
	    del login_session['picture']

	    response = make_response(json.dumps('Successfully disconnected.'), 200)
	    response.headers['Content-Type'] = 'application/json'
	    return response
	else:
	    # For whatever reason, the given token was invalid.
	    response = make_response(
	        json.dumps('Failed to revoke token for given user.'), 400)
	    response.headers['Content-Type'] = 'application/json'
	    return response


"""Users (next section)"""

# User helper functions
def createUser(login_session):
	newUser = User(name = login_session['username'], email = 
	    login_session['email'], picture = login_session['picture'])
	session.add(newUser)
	session.commit()

	user = session.query(User).filter_by(email = login_session['email']).one()
	return user.id 

# Return ID of a user when email provided
def getUserID(email):
	try:
	    user = session.query(User).filter_by(email = email).one()
	    return user.id 
	except:
	    return None

# If user ID given, returns user object w/ info
def getUserInfo(user_id):
	user = session.query(User).filter_by(id = user_id).one()
	return user


"""API END-POINTS (GET requests)"""

# JSON for all restaurants
@app.route('/restaurants/JSON')
def restaurantsJSON():
	restaurants = session.query(Restaurant).all()

	return jsonify(Restaurants=[r.serialize for r in restaurants])

# JSON for a full menu for a specific restaurant
@app.route('/restaurants/<int:restaurant_id>/menu/JSON')
def menuJSON(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)
	
	return jsonify(MenuItems=[i.serialize for i in items])


# JSON for a specific menu item
@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
	menuItem = session.query(MenuItem).filter_by(id = menu_id).one()

	return jsonify(MenuItem = menuItem.serialize)

"""Routes and CRUD functionality for each template/area on site"""

@app.route('/')
@app.route('/restaurants')
def showRestaurants():
	restaurants = session.query(Restaurant).all()

	return render_template('restaurants.html', restaurants = restaurants)
	#return "This page will show all my restaurants"


@app.route('/restaurants/new', methods=['GET', 'POST'])
def newRestaurant():
	if 'username' not in login_session:
		return redirect('/login')

	if request.method == 'POST':
		newRestaurant = Restaurant(name = request.form['name'], user_id=login_session['user_id'])
		session.add(newRestaurant)
		flash("New Restaurant %s Created!" % newRestaurant.name)
		session.commit()

		return redirect(url_for('showRestaurants'))

	else:
		return render_template('newRestaurant.html')


@app.route('/restaurants/<int:restaurant_id>/edit', methods = ['GET', 'POST'])
def editRestaurant(restaurant_id):
	if 'username' not in login_session:
		return redirect('/login')

	editedRestaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if request.method == 'POST':
		if request.form['name']:
			editedRestaurant.name = request.form['name']
			# session.add(editedRestaurant)
			# session.commit()
			flash("Restaurant Successfully Edited!!")

			return redirect(url_for('showRestaurants'))
	else:
		return render_template('editRestaurant.html', restaurant_id=restaurant_id, restaurant=editedRestaurant)



@app.route('/restaurants/<int:restaurant_id>/delete', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
	if 'username' not in login_session:
		return redirect('/login')

	restaurantToDelete = session.query(Restaurant).filter_by(id=restaurant_id).one()
	if request.method == 'POST':
		session.delete(restaurantToDelete)
		flash("Restaurant Successfully Deleted!!")
		session.commit()

		return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
	else:
		return render_template('deleteRestaurant.html', restaurant = restaurantToDelete)

	#return "This page will be for deleting restaurant %s" % restaurant_id


@app.route('/restaurants/<int:restaurant_id>')
@app.route('/restaurants/<int:restaurant_id>/menu')
def showMenu(restaurant_id):
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	items = session.query(MenuItem).filter_by(restaurant_id=restaurant_id)

	return render_template('menu.html', restaurant=restaurant, items=items)

	#return "This page is the menu for restaurant %s" % restaurant_id




@app.route('/restaurants/<int:restaurant_id>/menu/new', methods = ['GET', 'POST'])
def newMenuItem(restaurant_id):
	if 'username' not in login_session:
		return redirect('/login')

	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()

	if request.method == 'POST':
		newItem = MenuItem(name = request.form['name'], description = request.form['description'], 
			price = request.form['price'], course = request.form['course'], 
			restaurant_id = restaurant_id, user_id=restaurant.user_id)
		session.add(newItem)
		session.commit()
		flash('New Menu %s Item Successfully Created' % (newItem.name))

		return redirect(url_for('showMenu', restaurant_id = restaurant_id))

	else:
		return render_template('newItem.html', restaurant_id=restaurant_id)
	
	#return "This page is for making a new menu item for restaurant %s" % restaurant_id




@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/edit', methods = ['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
	if 'username' not in login_session:
		return redirect('/login')

	editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()

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
		return render_template('editItem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editedItem)

	# return "This page is for editing menu item %s for restaurant %s" % (menu_id, restaurant_id)




@app.route('/restaurants/<int:restaurant_id>/menu/<int:menu_id>/delete', methods = ['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
	if 'username' not in login_session:
		return redirect('/login')

	restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
	itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
	if request.method == 'POST':
		session.delete(itemToDelete)
		session.commit()
		flash("Menu Item Successfully Deleted!!")

		return redirect(url_for('showMenu', restaurant_id=restaurant_id))

	else:
		return render_template('deleteItem.html', item = itemToDelete)

	#return "This page is for deleting menu item %s from the restaurant %s" % (menu_id, restaurant_id)



"""End bit"""

if __name__ == '__main__':
	app.secret_key = "super secret key"
	app.debug = True
	app.run(host = '0.0.0.0', port = 5000)



# Unused -- various options I've tried for gdisconnect

# GOOGLE disconnect route and fx
# @app.route('/gdisconnect')
# def gdisconnect():
#     # Execute HTTP GET request to revoke current token

# 	access_token = login_session.get('access_token')
# 	#access_token = login_session['credentials']
# 	#access_token = credentials.access_token
# 	#access_token = login_session.get('credentials')
# 	print 'In gdisconnect access token is %s' % access_token
# 	print 'Username is: ' 
# 	print login_session['username']

# 	if access_token is None:
# 	    print 'Access Token is None'
# 	    response = make_response(json.dumps('Current user not connected.'), 401)
# 	    response.headers['Content-Type'] = 'application/json'
# 	    return response
# 	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']  #original code
# 	#url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session.get('access_token')
# 	#url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['credentials']
# 	#url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token

# 	h = httplib2.Http()
# 	result = h.request(url, 'GET')[0]
# 	print 'result is: '
# 	print result

# 	# if request successful, successfully disconnected users acc
# 	# depopulate login session accordingly
# 	if result['status'] == '200':
# 	    #del login_session['access_token'] 
# 	    del login_session['credentials'] 
# 	    del login_session['gplus_id']
# 	    del login_session['username']
# 	    del login_session['email']
# 	    del login_session['picture']
# 	    response = make_response(json.dumps('Successfully disconnected.'), 200)
# 	    response.headers['Content-Type'] = 'application/json'
# 	    return response
# 	else:

# 	    response = make_response(json.dumps('Failed to revoke token for given user.', 400))
# 	    response.headers['Content-Type'] = 'application/json'
# 	    return response