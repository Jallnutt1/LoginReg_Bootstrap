from django.shortcuts import render, redirect
from django.contrib import messages
from .models import *
import bcrypt

def index(request):
    return render(request, 'LoginReg/index.html')

def register(request):
    if request.method == "POST":
        errors = User.objects.reg_validator(request.POST)
        if errors:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/')
        else:
            hash_password=bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode()
            user = User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], birthday=request.POST['birthday'], email=request.POST['email'], password=hash_password)
            request.session['user_id'] = user.id
            return redirect('/login')

def login(request):
    if request.method == "POST":
        errors = User.objects.login_validator(request.POST)
        if errors:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect('/')
        else:
            user = User.objects.filter(email=request.POST['email'])
            loggedin_user = user[0]
            request.session['user_id'] = loggedin_user.id
            return redirect('/login')
    else:
        context={
            'user':User.objects.get(id=request.session['user_id'])
        }
        return render(request, 'loginReg/login.html', context)

def show_all(request):
    context={
        'users':User.objects.all()
    }
    return render(request, 'loginReg/show_all.html', context)

def delete(request, user_id):
    user_to_delete = User.objects.get(id=user_id)
    user_to_delete.delete()
    return redirect('/')

def update(request):
    if request.method == "POST":
        errors = User.objects.update_validator(request.POST)
        if errors:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect("/update")
        else:
            user_update = User.objects.get(id=request.session['user_id'])
            user_update.first_name = request.POST['first_name']
            user_update.last_name = request.POST['last_name']
            user_update.birthday = request.POST['birthday']
            user_update.email = request.POST['email']
            user_update.save()
            # return redirect("/success")
            return redirect("/login")
    else:
        loggedin_user = User.objects.get(id=request.session['user_id'])
        context={
            'user':loggedin_user,
            'birthday':str(loggedin_user.birthday)
        }
        return render(request, 'loginReg/update.html', context)

def change_password(request):
    if request.method =="GET":
        context={
            'user':User.objects.get(id=request.session['user_id'])
        }
        return render(request, 'loginReg/change_password.html', context)
    else:
        errors = User.objects.password_change_validator(request.POST)
        if errors:
            for key, value in errors.items():
                messages.error(request, value)
            return redirect("/change_password")
        else:
            hash_password = bcrypt.hashpw(request.POST['new_password'].encode(), bcrypt.gensalt()).decode()
            user_to_update = User.objects.get(id=request.session['user_id'])
            user_to_update.password = hash_password
            user_to_update.save()
            return redirect("/login")

def logout(request):
    request.session.flush()
    return redirect('/')