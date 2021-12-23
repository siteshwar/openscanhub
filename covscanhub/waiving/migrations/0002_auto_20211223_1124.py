# Generated by Django 2.2.24 on 2021-12-23 11:24

from django.db import migrations, models
import django.db.models.deletion
import kobo.django.fields


class Migration(migrations.Migration):

    dependencies = [
        ('waiving', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='checker',
            name='group',
            field=models.ForeignKey(blank=True, help_text='Name of group where does this checker belong', null=True, on_delete=django.db.models.deletion.CASCADE, to='waiving.CheckerGroup', verbose_name='Checker group'),
        ),
        migrations.AlterField(
            model_name='checker',
            name='name',
            field=models.CharField(max_length=64, verbose_name="Checker's name"),
        ),
        migrations.AlterField(
            model_name='checker',
            name='severity',
            field=models.PositiveIntegerField(choices=[(0, 'NO_EFFECT'), (1, 'FALSE_POSITIVE'), (2, 'UNCLASSIFIED'), (3, 'CONFUSION'), (4, 'SECURITY'), (5, 'ROBUSTNESS')], default=0, help_text='Severity of checker that the defect represents'),
        ),
        migrations.AlterField(
            model_name='checkergroup',
            name='enabled',
            field=models.BooleanField(default=True, help_text='User may waive only ResultGroups which belong to enabled CheckerGroups'),
        ),
        migrations.AlterField(
            model_name='checkergroup',
            name='name',
            field=models.CharField(max_length=64, verbose_name="Checker's name"),
        ),
        migrations.AlterField(
            model_name='defect',
            name='annotation',
            field=models.CharField(blank=True, max_length=32, null=True, verbose_name='Annotation'),
        ),
        migrations.AlterField(
            model_name='defect',
            name='checker',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='waiving.Checker', verbose_name='Checker'),
        ),
        migrations.AlterField(
            model_name='defect',
            name='cwe',
            field=models.IntegerField(blank=True, null=True, verbose_name='CWE'),
        ),
        migrations.AlterField(
            model_name='defect',
            name='defect_identifier',
            field=models.CharField(blank=True, max_length=16, null=True, verbose_name='Defect Identifier'),
        ),
        migrations.AlterField(
            model_name='defect',
            name='events',
            field=kobo.django.fields.JSONField(default=[], help_text='List of defect related events.'),
        ),
        migrations.AlterField(
            model_name='defect',
            name='function',
            field=models.CharField(blank=True, help_text='Name of function that contains current defect', max_length=128, null=True, verbose_name='Function'),
        ),
        migrations.AlterField(
            model_name='defect',
            name='key_event',
            field=models.IntegerField(help_text='Event that resulted in defect', verbose_name='Key event'),
        ),
        migrations.AlterField(
            model_name='defect',
            name='order',
            field=models.IntegerField(help_text='Defects in view have fixed order.', null=True),
        ),
        migrations.AlterField(
            model_name='defect',
            name='state',
            field=models.PositiveIntegerField(choices=[(0, 'NEW'), (1, 'OLD'), (2, 'FIXED'), (3, 'UNKNOWN'), (4, 'PREVIOUSLY_WAIVED')], default=3, help_text='Defect state'),
        ),
        migrations.AlterField(
            model_name='result',
            name='lines',
            field=models.IntegerField(blank=True, help_text='Lines of code scanned', null=True),
        ),
        migrations.AlterField(
            model_name='result',
            name='scanner',
            field=models.CharField(blank=True, help_text='DEPRECATED, not used anymore', max_length=32, null=True, verbose_name='Analyser'),
        ),
        migrations.AlterField(
            model_name='result',
            name='scanner_version',
            field=models.CharField(blank=True, help_text='DEPRECATED, not used anymore', max_length=32, null=True, verbose_name="Analyser's Version"),
        ),
        migrations.AlterField(
            model_name='result',
            name='scanning_time',
            field=models.IntegerField(blank=True, null=True, verbose_name='Time spent scanning'),
        ),
        migrations.AlterField(
            model_name='resultgroup',
            name='checker_group',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='waiving.CheckerGroup', verbose_name='Group of checkers'),
        ),
        migrations.AlterField(
            model_name='resultgroup',
            name='defect_type',
            field=models.PositiveIntegerField(choices=[(0, 'NEW'), (1, 'OLD'), (2, 'FIXED'), (3, 'UNKNOWN'), (4, 'PREVIOUSLY_WAIVED')], default=3, help_text='Type of defects that are associated with this group.'),
        ),
        migrations.AlterField(
            model_name='resultgroup',
            name='defects_count',
            field=models.PositiveSmallIntegerField(blank=True, default=0, null=True, verbose_name='Number of defects associated with this group.'),
        ),
        migrations.AlterField(
            model_name='resultgroup',
            name='result',
            field=models.ForeignKey(help_text='Result of scan', on_delete=django.db.models.deletion.CASCADE, to='waiving.Result', verbose_name='Result'),
        ),
        migrations.AlterField(
            model_name='resultgroup',
            name='state',
            field=models.PositiveIntegerField(choices=[(0, 'NEEDS_INSPECTION'), (1, 'WAIVED'), (2, 'INFO'), (3, 'PASSED'), (4, 'UNKNOWN'), (5, 'PREVIOUSLY_WAIVED'), (6, 'CONTAINS_BUG')], default=4, help_text='Type of waiver'),
        ),
        migrations.AlterField(
            model_name='waiver',
            name='message',
            field=models.TextField(verbose_name='Message'),
        ),
        migrations.AlterField(
            model_name='waiver',
            name='result_group',
            field=models.ForeignKey(help_text='Group of defects which is waived for specific Result', on_delete=django.db.models.deletion.CASCADE, to='waiving.ResultGroup'),
        ),
        migrations.AlterField(
            model_name='waiver',
            name='state',
            field=models.PositiveIntegerField(choices=[(0, 'NOT_A_BUG'), (1, 'IS_A_BUG'), (2, 'FIX_LATER'), (3, 'COMMENT')], default=1, help_text='Type of waiver'),
        ),
        migrations.AlterField(
            model_name='waivinglog',
            name='state',
            field=models.PositiveIntegerField(choices=[(0, 'NEW'), (1, 'DELETE'), (2, 'REWAIVE')], help_text='Waiving action'),
        ),
    ]
