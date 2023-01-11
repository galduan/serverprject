import hashlib
import json
import os
import random
import string

from django.contrib.auth import logout, authenticate, login, get_user_model
from django.contrib.auth.hashers import check_password
from django.core.mail import send_mail
from django.forms.models import model_to_dict
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from users.models import UsersData

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@csrf_exempt
def register(request):
    users = None
    if request.method == 'POST':
        body_unicode = request.body.decode('utf-8')
        data = json.loads(body_unicode) or None
        if (not is_valid_password(data['password'])):
            return JsonResponse(
                {"error": "The password you entered does not meet the requirements, please try again."})
        elif not is_difference_password(data['password'], data['password_repeat']):
            return JsonResponse(
                {"error": "The passwords do not match, please try again."})
        else:
            username_check = data['username']
            user = UsersData.objects.raw(
                f"SELECT * FROM users_usersdata WHERE username = '%s'" % (username_check))
            if (len(list(user)) != 0):
                return JsonResponse({"error": "The user name is not valid"})
            else:
                user = UsersData.objects.create_user(
                    data['username'],
                    data['email'],
                    data['password']
                )
                user.first_name = data['firstname']
            user.last_name = data['last_name']
            passwordsObj = [
                {
                    "passwords": [data['password']]
                }
            ]
            user.lastPasswords = json.dumps(passwordsObj)
            user.save()
            user = model_to_dict(user)
            return JsonResponse({"userName": data['username']})
    else:
        return JsonResponse({"error": "please try again"})


@csrf_exempt
def login_request(request):
    users = None
    badPass = None
    tooManyAttemps = None
    if request.COOKIES:
        attemps_number = int(request.COOKIES['attemps_number'])
    else:
        attemps_number = 0
    # Parse the POST data as a JSON object
    data = json.loads(request.body)

    # Get the form data from the dictionary
    email = data.get('email', None)
    password = data.get('password', None)
    username = None
    if email and password:
        user = UsersData.objects.raw(
            f"SELECT * FROM users_usersdata WHERE email = '%s'" % (email))

        if (len(list(user)) == 1):
            matchcheck = check_password(password, user[0].password)
            if (matchcheck):
                username = user[0].username
                user = authenticate(request, username=username, password=password)
                login(request, user)
                # Return a JSON response with the necessary data
                response = JsonResponse({'status': 'success'})
                response.set_cookie("isAuthenticated", "true")
                response.set_cookie('attemps_number', 0)
                response.set_cookie("userName", username)
                return JsonResponse({'success': True, 'message': 'login success', "userName": username})
            else:
                # password not matched
                attemps_number = attemps_number + 1
                badPass = True
                return JsonResponse({'error': 'email or password wrong.'})
        else:
            # sqli
            users = list(user)
            attemps_number = attemps_number + 1
            return JsonResponse({'error': 'email or password wrong.'})
    req = load_user_create_requierments(
        "app/password_requirements.json")
    if (attemps_number >= req['login_attemps_limit']):
        tooManyAttemps = True
        return JsonResponse({'error': 'too Many Attemps'})
    return JsonResponse({'error': 'email or password wrong.'})
    # Return a JSON response with the necessary data


@csrf_exempt
def send_mail_view(request):
    if request.method == 'POST':
        # get the email from the POST request body
        body_unicode = request.body.decode('utf-8')
        data = json.loads(body_unicode) or None
        email = data['email']
        # get the user with the given email
        User = get_user_model()
        user = User.objects.filter(email=email).first()
        if user is not None:
            # generate a reset code and save it to the user's resetCode field
            reset_code = generate_reset_code()
            user.resetCode = reset_code
            user.save()
            # send an email to the user with the reset code
            subject = 'Forgot Password'
            message = 'Your reset code is: ' + reset_code
            from_email = 'galduan99@gmail.com'
            recipient_list = [email]
            send_mail(
                subject,
                message,
                from_email,
                recipient_list,
                fail_silently=False,
            )
            return JsonResponse({'status': 'success'})
        else:
            # email was not found in the database
            return JsonResponse({'error': 'Email not found'})
    else:
        # request method is not POST, return an error response
        return JsonResponse({'error': 'Invalid request method'})


def generate_reset_code():
    # generate a random string of letters and digits
    reset_code = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    # hash the reset code using SHA-1
    reset_code = hashlib.sha1(reset_code.encode()).hexdigest()
    return reset_code


@csrf_exempt
def verify_code(request):
    if request.method == 'POST':
        body_unicode = request.body.decode('utf-8')
        data = json.loads(body_unicode) or None
        input_email = data['email']
        input_code = data['reset_code']
        found_user = UsersData.objects.filter(
            email=input_email, resetCode=input_code)
        if found_user.exists():
            # login(request, found_user[0],
            #       backend='django.contrib.auth.backends.ModelBackend')
            # found_user = UsersData.objects.get(username=input_username)
            # found_user.resetCode = None
            # found_user.save()
            return JsonResponse({'success': True, 'message': 'code approved'})
        else:
            return JsonResponse({'error': 'Invalid code. Please try again.'})
    else:
        return JsonResponse({'error': 'Invalid request method.'})


@csrf_exempt
def change_pwd_with_mail(request):
    # Get the form data from the request
    body_unicode = request.body.decode('utf-8')
    data = json.loads(body_unicode)
    new_password = data['new_password']
    verify_password = data['verify_password']

    # Validate the form data
    if not is_difference_password(new_password, verify_password):
        return JsonResponse({'error': 'The passwords do not match, please try again.'})
    if not is_valid_password(new_password):
        return JsonResponse({'error': 'The password you entered does not meet the requirements, please try again.'}
                            )

    # Get the user object
    user = UsersData.objects.get(email=data['email'])
    if user is not None:
        # Check if the new password has already been used
        if passwordNotInLasts(user, new_password):
            # Set the new password and save the user object
            user.set_password(new_password)
            # user = authenticate(request, username=username, password=password)
            # login(request, user)
            user.resetCode = None
            user.save()
            return JsonResponse({'message': 'Password changed successfully', "userName": user.userName})
        else:
            return JsonResponse({'error': 'You already used this password, please try again.'})

    else:
        return JsonResponse({'error': 'There was an error, please try again.'})


@csrf_exempt
def logout_request(request):
    logout(request)
    return JsonResponse({"status": "You are logged out"})


@csrf_exempt
def user_change_pwd_view(request):
    # Get the form data from the request
    body_unicode = request.body.decode('utf-8')
    data = json.loads(body_unicode)
    existing_password = data['existing_password']
    new_password = data['new_password']
    verify_password = data['verify_password']

    # Validate the form data
    if not is_difference_password(new_password, verify_password):
        return JsonResponse({'error': 'The passwords do not match, please try again.'})
    if not is_valid_password(new_password):
        return JsonResponse({'error': 'The password you entered does not meet the requirements, please try again.'},
                            )

    # Get the user object
    user = UsersData.objects.get(username=data['username'])
    if user is not None:
        # Check the existing password
        if user.check_password(existing_password):
            # Check if the new password has already been used
            if passwordNotInLasts(user, new_password):
                # Set the new password and save the user object
                user.set_password(new_password)
                user.save()
                return JsonResponse({'error': 'Password changed successfully'})
            else:
                return JsonResponse({'error': 'You already used this password, please try again.'})
        else:
            return JsonResponse({'error': 'The existing password is not correct, please try again.'})
    else:
        return JsonResponse({'error': 'There was an error, please try again.'})


def is_difference_password(password, password_repeat):
    return password == password_repeat


def load_user_create_requierments(path_to_req):
    with open(os.path.join(BASE_DIR, path_to_req)) as file:
        data = json.load(file)
    return data


def is_valid_password(password):
    count_digit = sum(c.isdigit() for c in password)
    count_alpha = sum(c.isalpha() for c in password)
    count_lower = sum(c.islower() for c in password)
    count_upper = sum(c.isupper() for c in password)
    count_special_char = 0
    req = load_user_create_requierments(
        "app/password_requirements.json")
    for special_char in req['password_content']['special_characters']:
        count_special_char += password.count(special_char)

    if req['min_length'] > len(password):
        return False
    if count_digit < req['password_content']['min_length_digit']:
        return False
    if count_alpha < req['password_content']['min_length_alpha']:
        return False
    if count_lower < req['password_content']['min_length_lower']:
        return False
    if count_upper < req['password_content']['min_length_upper']:
        return False
    if count_special_char < req['password_content']['min_length_special']:
        return False
    return True


def passwordNotInLasts(user, new_password):
    policy = load_user_create_requierments(
        "app/password_requirements.json")
    if (policy['password_history'] <= 0):
        return True
    # First change (exisiting users before code change)
    if (user.lastPasswords == ''):
        passwordsObj = [
            {
                "passwords": [new_password]
            }
        ]
        user.lastPasswords = json.dumps(passwordsObj)
        user.save()
        return True
    else:
        passwordsObj = json.loads(user.lastPasswords)
        passwordsObj = passwordsObj[0]['passwords']
        for password in passwordsObj:
            if (password == new_password):
                return False
        # delete first saved password
        if (len(passwordsObj) == policy['password_history']):
            del passwordsObj[0]
        passwordsObj.append(new_password)
        passwordsObj = [
            {
                "passwords": passwordsObj
            }
        ]
        user.lastPasswords = json.dumps(passwordsObj)
        user.save()
        return True
