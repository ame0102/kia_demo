from django.shortcuts import render
from django.http import HttpResponse

def index(request):
    """Render the main application page"""
    return render(request, 'frontend/index.html')