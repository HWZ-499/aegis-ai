"""
TP: An arbitrary object.escape method is not proof of HTML escaping.
Expected: XSS_RISK
"""

from django.http import HttpResponse


class Formatter:
    def escape(self, value):
        return value


def profile(request):
    formatter = Formatter()
    return HttpResponse(formatter.escape(request.GET["name"]))
