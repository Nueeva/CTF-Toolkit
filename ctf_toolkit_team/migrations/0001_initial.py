from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True
    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(
            name="Case",
            fields=[("id", models.CharField(max_length=32, primary_key=True, serialize=False)),
                    ("title", models.CharField(max_length=200))],
        ),
        migrations.CreateModel(
            name="Membership",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ("role", models.CharField(choices=[("owner", "Owner"), ("editor", "Editor"), ("viewer", "Viewer")], max_length=6)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="team_app.case")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={"constraints": [models.UniqueConstraint(fields=("case", "user"), name="one_case_role_per_user")]},
        ),
        migrations.CreateModel(
            name="Invitation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ("digest", models.CharField(max_length=64, unique=True)),
                ("role", models.CharField(choices=[("owner", "Owner"), ("editor", "Editor"), ("viewer", "Viewer")], max_length=6)),
                ("expires_at", models.DateTimeField()),
                ("used_at", models.DateTimeField(null=True)),
                ("case", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to="team_app.case")),
            ],
        ),
    ]
