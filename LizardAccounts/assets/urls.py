from django.urls import path
from . import views

urlpatterns = [
    path('images/', views.images_view, name='images'),
    path('documents/', views.documents_view, name='documents'),
    path('confidential/', views.confidential_view, name='confidential'),
    path('serve/image/<int:image_id>/', views.serve_image, name='serve_image'),
    path('serve/document/<int:document_id>/', views.serve_document, name='serve_document'),
    path('preview/image/<int:image_id>/', views.image_preview, name='image_preview'),
]
