from flask import Blueprint, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import re
import requests
from datetime import datetime

views = Blueprint(__name__, 'views')

# The data is taken from the StatsBomb API which is open-source and free to use on github
# At first we get the list of competitions from the API and then we extract the leagues and seasons from the competitions
# To extact specific leage and season data we use the league and season ID from the competitions data
# Example: https://raw.githubusercontent.com/statsbomb/open-data/master/data/matches/43/3.json
# The above URL will give us the matches for the League with ID 43 and Season with ID 3
# We then can extract the team names from the matches and sort them by date using the fetch_team_info function

# getting the list of competitions from external API
competitions = requests.get('https://raw.githubusercontent.com/statsbomb/open-data/master/data/competitions.json').json()

# Create a dictionary for leagues and seasons
leagues = {}
seasons = {}

# Populate the leagues and seasons dictionaries
for competition in competitions:
    competition_id = competition['competition_id']
    season_id = competition['season_id']
    league_name = competition['competition_name']
    season_name = competition['season_name']
    
    if competition_id not in leagues:
        leagues[competition_id] = league_name
    
    if competition_id not in seasons:
        seasons[competition_id] = {}
    seasons[competition_id][season_id] = season_name

# Take a list of matches and return a list of unique team names
def extract_team_names(matches):
    teams = set()
    for match in matches:
        teams.add(match['home_team']['home_team_name'])
        teams.add(match['away_team']['away_team_name'])
    return list(teams)

# Function to fetch matches for a specific team and sort them by date
def fetch_team_info(matches, team_name):
    team_matches = [match for match in matches if match['home_team']['home_team_name'] == team_name or match['away_team']['away_team_name'] == team_name]
    team_matches.sort(key=lambda x: datetime.strptime(x['match_date'], '%Y-%m-%d'))
    return team_matches

# Check if username is already taken
def username_checker(username):
    with open('users.txt', 'r') as file:
        lines = file.readlines()
        usernames = [line.strip().split(',')[0] for line in lines]
        return username in usernames

# Function to validate the format and constraints of a username
def validate_username(username):
    # Check for length
    if len(username) < 3:
        return "Username must be at least 3 characters long."
    if len(username) > 15:
        return "Username must be a maximum of 15 characters long."
    
    # Check for spaces
    if ' ' in username:
        return "Username cannot contain spaces."
    
    # Check for non-latin characters
    if not re.match("^[a-zA-Z0-9!@#$%^&*()_+=-]*$", username):
        return "Username can only contain Latin letters, numbers, and special characters."
    return None

# Function to validate the format and constraints of a password
def validate_password(password):
    # Check for length
    if len(password) < 5:
        return "Password must be at least 5 characters long."
    if len(password) > 20:
        return "Password must be a maximum of 20 characters long."
    
    # Check for spaces
    if ' ' in password:
        return "Password cannot contain spaces."
    
    # Check for non-latin characters
    if not re.match("^[a-zA-Z0-9!@#$%^&*()_+=-]*$", password):
        return "Password can only contain Latin letters, numbers, and special characters."
    return None

# Check if user is logged in
def is_logged_in():
    return 'username' in session

# Logout by removing username from session
@views.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return "ok"

# Route to handle user registration
@views.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('views.home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username_checker(username):
            return render_template('register.html', error='Username is already taken!')
        
        if validate_username(username):
            return render_template('register.html', error=validate_username(username))
        
        if validate_password(password):
            return render_template('register.html', error=validate_password(password))
         
        hashed_password = generate_password_hash(password)
        with open('users.txt', 'a') as file:
            file.write(f'{username},{hashed_password}\n')
        
        return redirect(url_for('views.login'))
    return render_template('register.html')

# Route to handle user login
@views.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('views.home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with open('users.txt', 'r') as file:
            lines = file.readlines()
            for line in lines:
                stored_username, stored_password = line.strip().split(',')
                if stored_username == username and check_password_hash(stored_password, password):
                    session['username'] = username
                    return redirect(url_for('views.home'))
            
        return render_template('login.html', error='Invalid username or password!')
    return render_template('login.html')

# Route to handle updating a user's username
@views.route('/update_username', methods=['POST'])
def update_username():
    if 'username' in session:
        new_username = request.form.get('new_username')
        username = session['username']

        # Check if the new username is the same as the old username
        if new_username == username:
            return render_template('profile.html', username=username, error='New username cannot be the same as the old username!')
        
        # Check if the new username already exists
        if username_checker(new_username):
            return render_template('profile.html', username=username, error='Username already taken!')
        
        # Check username for validity
        if validate_username(new_username):
            return render_template('profile.html', username=username, error=validate_username(new_username))

        # Update the username in the file
        lines = []
        with open('users.txt', 'r') as file:
            lines = file.readlines()
        
        with open('users.txt', 'w') as file:
            for line in lines:
                stored_username, stored_password = line.strip().split(',')
                if stored_username == username:
                    file.write(f'{new_username},{stored_password}\n')
                    session['username'] = new_username
                else:
                    file.write(line)
        
        return render_template('profile.html', username=new_username, success='Username updated successfully!')
    return redirect(url_for('views.login'))

# Route to handle updating a user's password
@views.route('/update_password', methods=['POST'])
def update_password():
    if 'username' in session:
        username = session['username']
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        
        # Check if the old password matches
        lines = []
        with open('users.txt', 'r') as file:
            lines = file.readlines()
        
        for line in lines:
            stored_username, stored_password = line.strip().split(',')
            if stored_username == username and check_password_hash(stored_password, old_password):
                # Update the password in the file
                if old_password == new_password:
                    return render_template('profile.html', username=username, error='New password cannot be the same as the old password!')
                
                # Check password for validity
                if validate_password(new_password):
                    return render_template('profile.html', username=username, error=validate_password(new_password))
                
                hashed_password = generate_password_hash(new_password)
                with open('users.txt', 'w') as file:
                    for line in lines:
                        if stored_username in line:
                            file.write(f'{username},{hashed_password}\n')
                        else:
                            file.write(line)
                return render_template('profile.html', username=username, success='Password updated successfully!')
        
        return render_template('profile.html', username=username, error='Incorrect old password!')
    return redirect(url_for('views.login'))

# Route to display the home page
@views.route('/')
def home():
    if not is_logged_in():
        return redirect(url_for('views.login'))
    else:
        # Parameters to specify league and season for fetching team data
        selected_league = request.args.get('league', type=int) # League ID parameter
        selected_season = request.args.get('season', type=int) # Season ID parameter
    
        teams = []
        if selected_league and selected_season:
            try:
                # Fetch matches based on selected league and season
                matches = requests.get(f'https://raw.githubusercontent.com/statsbomb/open-data/master/data/matches/{selected_league}/{selected_season}.json').json()
                team_names = set()
                for match in matches:
                    team_names.add(match['home_team']['home_team_name'])
                    team_names.add(match['away_team']['away_team_name'])
                teams = sorted(team_names)
            except Exception as e:
                print(e)   
    return render_template('home.html', leagues=leagues, seasons=seasons, team_names=teams, selected_league=selected_league, selected_season=selected_season)

# Route to display the user's profile
@views.route('/profile')
def profile():
    if not is_logged_in():
        return redirect(url_for('views.login'))
    else:
        username = session['username']
        return render_template('profile.html', username=username)

# Route to display information about a specific team
@views.route('/team/<team_name>')
def team_info(team_name):
    if not is_logged_in():
        return redirect(url_for('views.login'))
    else:
        # Parameters to specify league and season for fetching match data
        league = request.args.get('league', type=int) # League ID parameter
        season = request.args.get('season', type=int) # Season ID parameter
        
        matches = []
        if league and season:
            try:
                 # Fetch matches based on specified league and season
                matches = requests.get(f'https://raw.githubusercontent.com/statsbomb/open-data/master/data/matches/{league}/{season}.json').json()
                team_matches = fetch_team_info(matches, team_name)
            except Exception as e:
                print(e)
    return render_template('team_info.html', team_name=team_name, matches=team_matches) 
