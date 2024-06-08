import os

from flask_migrate import Migrate

from app import create_app, db
from app.models import User, Role


app = create_app('default')
migrate = Migrate(app, db)


# CLI cmd
@app.cli.command('create-roles')
def create_roles():
    roles = ['User', 'Administrator']
    db_roles = [Role(name=role_name) for role_name in roles]
    db.session.add_all(db_roles)
    db.session.commit()


@app.cli.command('create-admin')
def create_admin():
    role = Role.query.filter_by(name='Administrator').first()
    admin = User(
        username=os.getenv('ADMIN_USERNAME') or 'admin',
        email=os.getenv('ADMIN_EMAIL') or 'wickyamala@gmail.com',
        password=os.getenv('ADMIN_PASSWORD') or 'admin',
        role=role
    )
    db.session.add(admin)
    db.session.commit()
    print('Admin created')


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role)
