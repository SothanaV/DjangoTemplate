# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.conf import settings
import sys
from django.contrib.auth.forms import PasswordChangeForm, UserCreationForm                              
from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User
# Create your views here.
def signup(request):
    if request.method == 'POST' and 'username' in request.POST:
        form = UserCreationForm(request.POST)
        username = request.POST['username']
        password = request.POST['password']
        password2 = request.POST['Check_password']
        email = request.POST['Email']
        fullname = request.POST['Fullname']
        lastname = request.POST['Lastname']
        if password==password2:
            user = authenticate(username=username, password=password)
            if user is not None:
                return redirect('singup')
            else:
                print password
                print username
                print user
                password1 = password
                #return redirect('signin')
                user = User.objects.create_user(
                    username=username,
                    password=password1,
                    email=email,
                    first_name=fullname,
                    last_name=lastname,
                    )
                return redirect('class_page')  
        else:
            print "UnmatchPassword"    
    else:
        form = UserCreationForm()
    return render(request, 'signup2.html', {'form': form})
def signin(request):
	if request.method == 'POST' and 'username' in request.POST:
		username = request.POST['username']
		password = request.POST['password']
		user = authenticate(username=username, password=password)
		print >>sys.stderr, "debug"
		if user is not None:
			if user.is_active:

				if 'remember' in request.POST:
					print>>sys.stderr, "%s type: %s"%(request.POST['remember'],type(request.POST['remember']))
					if request.POST['remember']=='1':
						request.session.set_expiry(604800) #remember keep session for a week
				else:
					request.session.set_expiry(14400) #not remember keep session for 4hrs
				print >>sys.stderr, "session expiry: %s"%request.session.get_expiry_age()

				login(request, user)
				if 'username' in request.session:
					print >>sys.stderr, "username_i: %s"%request.session['username']
				request.session['username'] = user.username
				print >>sys.stderr, "username_f: %s"%request.session['username']
				
				return redirect('class_page')
			else:
				msg="Disabled account"
		else:
			msg="Invalid username or password"
		return render(request,'login.html',{'msg': msg})   
	return render(request,'login.html',{'msg': ""})

def signout(request):
	print "signout"
	if 'username' in request.session:
		del request.session['username']
		print "del uname"
	logout(request)
	return redirect('class_page')

@login_required(login_url='signin')

def change_password(request):
    form = PasswordChangeForm(user=request.user)
    print >>sys.stderr, "request.user: %s"%request.user
    if request.method == 'POST':
        form = PasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            return redirect('class_page')

    return render(request, 'change_password.html', {
        'form': form,
    })