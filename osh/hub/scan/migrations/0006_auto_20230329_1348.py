# Generated by Django 2.2.24 on 2023-03-29 13:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scan', '0005_package_priority_offset'),
    ]

    operations = [
        migrations.AlterField(
            model_name='package',
            name='blocked',
            field=models.BooleanField(blank=True, default=False, help_text='If this is set to True, the package is blacklisted -- not accepted for scanning.', null=True),
        ),
        migrations.AlterField(
            model_name='package',
            name='eligible',
            field=models.BooleanField(blank=True, default=True, help_text='DEPRECATED, do not use; use package attribute instead.', null=True),
        ),
    ]
