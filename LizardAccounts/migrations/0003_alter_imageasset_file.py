

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('LizardAccounts', '0002_confidentialasset_documentasset_imageasset_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='imageasset',
            name='file',
            field=models.ImageField(upload_to=''),
        ),
    ]
