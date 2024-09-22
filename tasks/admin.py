from django.contrib import admin
from .models import Customer, Task, Member, Team, ProgressReport, Role, Profile, Admin

admin.site.register(Customer)
admin.site.register(Task)
admin.site.register(Member)
admin.site.register(Team)
admin.site.register(ProgressReport)
admin.site.register(Role)
admin.site.register(Profile)
admin.site.register(Admin)
