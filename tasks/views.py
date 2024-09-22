from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.generic import View
from .models import Customer, Task, Member, Team, ProgressReport
import json
from datetime import date, datetime, time
import requests
from django.http import JsonResponse
import calendar
from os import name
from django.shortcuts import render, get_object_or_404
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe
from django.utils.timezone import make_aware
from django_celery_beat.models import PeriodicTask, ClockedSchedule
from django.db import transaction, IntegrityError
from django.core.mail import EmailMessage
from rest_framework.exceptions import ParseError, ValidationError
from django.core.exceptions import ObjectDoesNotExist

from rest_framework import generics
from django.utils.crypto import get_random_string
import jwt
import jwt
import uuid
import pytz
from django.db.models import IntegerField
from django.db.models.functions import Cast
from rest_framework.exceptions import AuthenticationFailed
from datetime import datetime, timedelta
from rest_framework.response import Response
from django.core.mail import EmailMessage, BadHeaderError
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.forms.models import model_to_dict


from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.utils import timezone
from django.middleware.csrf import get_token
from django.views.decorators.csrf import ensure_csrf_cookie
import json
import string
import random
from django.db.models import Q, Min
from collections import defaultdict
from django.db.models import Avg
from rest_framework import status
from rest_framework.views import APIView

from django.db.models import Count, Sum, Case, When, IntegerField
import io
from openpyxl import Workbook
from openpyxl.styles import Font
from rest_framework import generics
from django.db.models import Subquery, OuterRef, Value, BooleanField
from .serializers import (
    UserSerializer,
    AdminDepthOneSerializer,
    CustomerSerializer,
    MemberSerializer,
    TaskSerializer,
    TesmSerializer,
)

from django_rest_passwordreset.models import ResetPasswordToken
from django_rest_passwordreset.serializers import EmailSerializer
from django_rest_passwordreset.tokens import get_token_generator


from urllib.parse import urlencode

import os

# Create your views here.

import environ
from time import sleep

env = environ.Env()


@api_view(["GET"])
@ensure_csrf_cookie
def get_csrf(request):
    response = Response({"detail": "CSRF cookie set"})
    response["X-CSRFToken"] = get_token(request)
    return response


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    data = request.data
    print(data)
    username = data.get("username")
    password = data.get("password")
    platform = data.get("platform", "unknown")
    if username is None or password is None:
        raise ValidationError({"detail": "Please provide username and password."})
    user = authenticate(request, username=username, password=password)

    if user is None:
        raise AuthenticationFailed({"detail": "Invalid credentials."})

    last_login = user.last_login
    login(request, user)
    user_data = get_user_data(user)
    print(user_data)
    if user_data:
        login_timestamp = timezone.now()

        response = Response(
            {
                "detail": "Successfully logged in.",
                "user": {**user_data, "last_login": last_login},
            }
        )
        response["X-CSRFToken"] = get_token(request)
        return response
    else:
        logout(request)
        return Response({"error": "Invalid user type"}, status=400)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def logout_view(request):
    if not request.user.is_authenticated:
        raise AuthenticationFailed({"detail": "You're not logged in."})

    logout(request)
    return Response({"detail": "Successfully logged out."})


@api_view(["GET"])
@permission_classes([AllowAny])
@ensure_csrf_cookie
def session_view(request):
    user = request.user
    last_login = user.last_login
    user_data = get_user_data(user)
    if user_data:
        response = Response(
            {
                "isAuthenticated": True,
                "user": {**user_data, "last_login": last_login},
            }
        )
        response["X-CSRFToken"] = get_token(request)
        return response
    else:
        return Response({"error": "Invalid user type"}, status=400)


def get_user_data(user):
    if not user.profile:
        return None
    elif user.profile.roles.exclude(name="vendor").count() == 0:
        return None
    user_profile_role = user.profile.roles.all().exclude(name="vendor").first().name
    roles = []
    for role in user.profile.roles.all():
        roles.append(role.name)
    if user_profile_role == "admin":
        serializer = AdminDepthOneSerializer(user.profile.admin)
    else:
        return None
    return {
        **serializer.data,
        "roles": roles,
        "user": {**serializer.data["user"], "type": user_profile_role},
    }


@api_view(["GET"])
@ensure_csrf_cookie
def get_csrf(request):
    response = Response({"detail": "CSRF cookie set"})
    response["X-CSRFToken"] = get_token(request)
    return response


class CustomerView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):

        customers = Customer.objects.all()
        serializer = CustomerSerializer(customers, many=True)
        return Response(serializer.data)

    def post(self, request):
        try:
            print(request.data)
            customer, created = Customer.objects.get_or_create(
                name=request.data.get("name"),
                email=request.data.get("email"),
                company=request.data.get("company"),
            )
            return Response({"message": "Customer Added Sucessfully."}, status=201)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to add customer"}, status=400)

    def put(self, request):
        try:
            customer_id = request.data.get("selectedCustomerId")
            values = request.data.get("values")
            customer = Customer.objects.get(id=int(customer_id))
            customer.name = values.get("name")
            customer.email = values.get("email")
            customer.company = values.get("company")
            customer.save()

            return Response({"message": "Customer Updated Sucessfully."}, status=201)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to update customer"}, status=400)

    def delete(self, request):
        try:
            customer_id = request.data.get("customerId")
            customer = Customer.objects.get(id=int(customer_id))
            customer.delete()

            return Response({"message": "Customer deleted Sucessfully."}, status=204)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to delete customer"}, status=400)


class TaskView(APIView):

    def get(self, request):

        tasks = Task.objects.all()
        serializer = TaskSerializer(tasks, many=True)
        return Response(serializer.data)

    def post(self, request):
        try:
            data = request.data
            title = data.get("title")
            description = data.get("description")
            customer_id = data.get("customer")
            team_id = data.get("team")
            submission_date_str = data.get("submission_date")
            budget = data.get("budget")

            # Convert submission date string to a datetime object
            submission_date = datetime.strptime(
                submission_date_str, "%Y-%m-%dT%H:%M:%S.%fZ"
            )

            # Fetch the customer and team objects based on the provided IDs
            customer = Customer.objects.get(pk=customer_id)
            team = Team.objects.get(pk=team_id)

            # Create a new Task object
            task = Task.objects.create(
                title=title,
                description=description,
                submission_date=submission_date,
                budget=budget,
                customer=customer,
                team=team,
            )

            return Response({"message": "Task added successfully."}, status=201)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to add Task."}, status=400)

    def put(self, request):
        try:
            task_id = request.data.get("selectedtaskId")
            data = request.data.get("values")
            title = data.get("title")
            description = data.get("description")
            customer_id = data.get("customer")
            team_id = data.get("team")
            submission_date_str = data.get("submission_date")
            budget = data.get("budget")

            # Convert submission date string to a datetime object
            submission_date = datetime.strptime(
                submission_date_str, "%Y-%m-%dT%H:%M:%S.%fZ"
            )

            # Fetch the customer and team objects based on the provided IDs
            customer = Customer.objects.get(pk=customer_id)
            team = Team.objects.get(pk=team_id)

            task = Task.objects.get(id=int(task_id))

            task.title = title
            task.description = description
            task.customer = customer
            task.team = team
            task.budget = budget
            task.submission_date = submission_date
            task.save()

            return Response({"message": "Customer Updated Sucessfully."}, status=201)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to update customer"}, status=400)

    def delete(self, request):
        try:
            task_id = request.data.get("taskId")
            task = Task.objects.get(id=int(task_id))
            task.delete()

            return Response({"message": "Customer deleted Sucessfully."}, status=204)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to delete customer"}, status=400)


class MemberView(APIView):

    permission_classes = [AllowAny]

    def get(self, request):

        members = Member.objects.all()
        serializer = MemberSerializer(members, many=True)
        return Response(serializer.data)

    def post(self, request):
        try:

            member = Member.objects.create(
                name=request.data.get("name"),
                email=request.data.get("email"),
                role=request.data.get("role"),
            )
            return Response({"message": "Member Added Sucessfully."}, status=201)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to add Member"}, status=400)

    def put(self, request):
        try:
            member_id = request.data.get("selectedMemberId")
            values = request.data.get("values")
            member = Member.objects.get(id=int(member_id))
            member.name = values.get("name")
            member.email = values.get("email")
            member.role = values.get("role")
            member.save()

            return Response({"message": "Member Updated Sucessfully."}, status=201)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to update member"}, status=400)

    def delete(self, request):
        try:
            member_id = request.data.get("memberId")
            member = Member.objects.get(id=int(member_id))
            member.delete()

            return Response({"message": "Member deleted Sucessfully."}, status=204)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to delete member"}, status=400)


class TeamView(APIView):

    def get(self, request):

        teams = Team.objects.all()
        serializer = TesmSerializer(teams, many=True)
        return Response(serializer.data)

    def post(self, request):
        try:

            team_name = request.data.get("name")
            member_ids = request.data.get("members", [])

            team = Team.objects.create(name=team_name)

            if member_ids:
                team.members.add(*member_ids)

            return Response(
                {"message": "Team Created Successfully."},
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            print(str(e))
            return Response(
                {"error": "Failed to create Team"}, status=status.HTTP_400_BAD_REQUEST
            )

    def put(self, request):
        try:
            team_id = request.data.get("selectedTeamId")
            values = request.data.get("values")
            team = Team.objects.get(id=int(team_id))
            team.name = values.get("name")
            team.members.set(values.get("members"))

            team.save()

            return Response({"message": "Team Updated Sucessfully."}, status=201)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to update team"}, status=400)

    def delete(self, request):
        try:

            team_id = request.data.get("teamId")

            team = Team.objects.get(id=int(team_id))
            team.delete()

            return Response({"message": "Team deleted Sucessfully."}, status=204)
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to delete team"}, status=400)


class ProgressReportView(APIView):

    def post(self, request):
        try:
            # Get data from the request
            progress_details = request.data.get("progress_details")
            task_id = request.data.get("task_id")

            # Create a new progress report instance
            progress_report = ProgressReport.objects.create(
                progress_details=progress_details
            )

            # Get the corresponding task instance
            task = Task.objects.get(id=int(task_id))

            # Add the progress report to the task's progress reports
            task.progress_reports.add(progress_report)

            return Response(
                {"message": "Progress report added successfully."}, status=201
            )
        except Exception as e:
            print(str(e))
            return Response({"error": "Failed to add progress report."}, status=400)


class CardsView(APIView):

    def get(self, request):

        tasks = Task.objects.all().count()
        customer=Customer.objects.all().count()
        member=Member.objects.all().count()
        team=Team.objects.all().count()
        temp = {
        "task": tasks,
        "customer": customer,
        "member": member,
        "team": team,
        }


        return Response(temp)
