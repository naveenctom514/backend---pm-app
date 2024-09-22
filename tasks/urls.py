from django.urls import path
from .views import CustomerView, TaskView, MemberView, TeamView, ProgressReportView,CardsView
from . import views

urlpatterns = [
    path("csrf/", views.get_csrf, name="api-csrf"),
    path("login/", views.login_view, name="api-login"),
    path("logout/", views.logout_view, name="api-logout"),
    path("session/", views.session_view, name="api-session"),
    path("customers/", CustomerView.as_view(), name="customer-list"),
    path("add/customers/", CustomerView.as_view(), name="customer-list"),
    path("customers/<int:pk>/", CustomerView.as_view(), name="customer-detail"),
    path("tasks/", TaskView.as_view(), name="task-list"),
    path("add/task/", TaskView.as_view(), name="task-list"),
    path("tasks/<int:pk>/", TaskView.as_view(), name="task-detail"),
    path("members/", MemberView.as_view(), name="member-list"),
    path("add/member/", MemberView.as_view(), name="member-list"),
    path("members/<int:pk>/", MemberView.as_view(), name="member-detail"),
    path("teams/", TeamView.as_view(), name="team-list"),
    path("add/team/", TeamView.as_view(), name="team-list"),
    path("teams/<int:pk>/", TeamView.as_view(), name="team-detail"),
    path(
        "progress-reports/", ProgressReportView.as_view(), name="progress-report-list"
    ),
    path(
        "progress-reports/<int:pk>/",
        ProgressReportView.as_view(),
        name="progress-report-detail",
    ),
    path(
        "add-progress-update/",
        ProgressReportView.as_view(),
       
    ),
     path(
        "cards/",
        CardsView.as_view(),
       
    ),
    
]
