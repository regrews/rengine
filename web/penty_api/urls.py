from django.urls import path

from penty_api import views

app_name = 'penty_api'

urlpatterns = [
    path('health/', views.HealthView.as_view(), name='health'),
    path('tasks-catalog/', views.TasksCatalogView.as_view(), name='tasks-catalog'),

    path('projects/', views.ProjectListView.as_view(), name='projects'),

    path('targets/', views.TargetListView.as_view(), name='targets'),
    path('targets/<int:pk>/', views.TargetDetailView.as_view(), name='target-detail'),

    path('engines/', views.EngineListView.as_view(), name='engines'),
    path('engines/<int:pk>/', views.EngineDetailView.as_view(), name='engine-detail'),

    path('scans/', views.ScanListView.as_view(), name='scans'),
    path('scans/<int:pk>/', views.ScanDetailView.as_view(), name='scan-detail'),
    path('scans/<int:pk>/stop/', views.ScanStopView.as_view(), name='scan-stop'),
    path('scans/<int:pk>/activity/', views.ScanActivityView.as_view(), name='scan-activity'),
    path('scans/<int:pk>/results/<str:kind>/', views.ScanResultsView.as_view(), name='scan-results'),

    path('subscans/', views.SubscanListView.as_view(), name='subscans'),
    path('subscans/<int:pk>/', views.SubscanDetailView.as_view(), name='subscan-detail'),
    path('subscans/<int:pk>/stop/', views.SubscanStopView.as_view(), name='subscan-stop'),
    path('subscans/<int:pk>/results/<str:kind>/', views.SubscanResultsView.as_view(), name='subscan-results'),
]
