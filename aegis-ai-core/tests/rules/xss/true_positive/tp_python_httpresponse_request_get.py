"""
TP: Django HttpResponse constructor writes user input to the HTTP response.
Expected: XSS_RISK
"""

from django.http import HttpResponse


def profile(request):
    return HttpResponse(request.GET["name"])
