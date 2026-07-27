from django.http import HttpResponseRedirect


def dashboard():
    return HttpResponseRedirect("/dashboard")
