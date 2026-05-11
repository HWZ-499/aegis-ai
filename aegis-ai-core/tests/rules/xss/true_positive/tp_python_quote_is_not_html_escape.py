"""
TP: URL quoting is not HTML-context escaping and must not suppress XSS.
Expected: XSS_RISK
"""

from urllib.parse import quote

from django.http import HttpResponse


def profile(request):
    return HttpResponse(quote(request.GET["next"]))
