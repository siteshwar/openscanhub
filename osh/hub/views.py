from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.contrib.auth.backends import ModelBackend

from kobo.django.xmlrpc.auth import login_password
from kobo.django.auth.models import User

class KoboUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

def register(request):
    if request.user.is_authenticated:
        return redirect("index")

    if request.method == "POST":
        form = KoboUserForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password1")
            login_password(request, username, password)
            return redirect("index")
    else:
        form = KoboUserForm()

    return render(request, "register.html", {"form": form})
