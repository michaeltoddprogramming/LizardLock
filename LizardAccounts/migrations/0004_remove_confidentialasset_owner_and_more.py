

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('LizardAccounts', '0003_alter_imageasset_file'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='confidentialasset',
            name='owner',
        ),
        migrations.RemoveField(
            model_name='documentasset',
            name='owner',
        ),
        migrations.RemoveField(
            model_name='imageasset',
            name='owner',
        ),
    ]
