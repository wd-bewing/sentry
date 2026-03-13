# Reuse hash column for SHA-256: widen to 64 chars. Legacy rows keep 32-char MD5; new rows use 64-char SHA-256.

from django.db import migrations, models

from sentry.new_migrations.migrations import CheckedMigration


class Migration(CheckedMigration):
    is_post_deployment = False

    dependencies = [
        ("sentry", "1052_rename_regionoutbox_to_celloutbox"),
    ]

    operations = [
        migrations.AlterField(
            model_name="grouphash",
            name="hash",
            field=models.CharField(max_length=64),
        ),
    ]
