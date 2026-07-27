from django.http import HttpResponseRedirect


def forward(request):
    target = request.GET.get("next")
    return HttpResponseRedirect(target)
