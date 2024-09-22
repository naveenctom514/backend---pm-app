from django.db import models
from django.contrib.auth.models import User


class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def _str_(self):
        return self.name


class Profile(models.Model):
    user_types = [
        ("admin", "admin"),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    roles = models.ManyToManyField(Role)

    def _str_(self):
        return self.user.username


class Admin(models.Model):
    user = models.OneToOneField(Profile, on_delete=models.CASCADE, blank=True)
    name = models.CharField(max_length=50)
    email = models.EmailField()
    phone = models.CharField(max_length=25)
    room_id = models.CharField(max_length=50, blank=True)

    def _str_(self):
        return self.name


class Customer(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    company = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return self.name


class Member(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    role = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class Team(models.Model):
    name = models.CharField(max_length=100)
    members = models.ManyToManyField(Member)

    def __str__(self):
        return self.name


class ProgressReport(models.Model):
    date = models.DateField(auto_now_add=True)
    progress_details = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"Progress report for {self.team} on {self.date}"


class Task(models.Model):
    title = models.CharField(max_length=100, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    submission_date = models.DateField(blank=True, null=True)
    budget = models.CharField(max_length=100, blank=True, null=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    progress = models.PositiveIntegerField(default=0)
    team = models.ForeignKey(Team, on_delete=models.CASCADE, blank=True, null=True)
    progress_reports = models.ManyToManyField(ProgressReport, blank=True)

    def __str__(self):
        return self.title
