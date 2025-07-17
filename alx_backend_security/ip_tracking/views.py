from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django_ratelimit.decorators import ratelimit
from django.http import HttpResponse
# Create your views here.

@csrf_exempt
@ratelimit(key='user', rate='10/m', method='POST', block=True)
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    return HttpResponse("Login success")