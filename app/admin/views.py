from flask import render_template, redirect, url_for, flash, request
from . import admin
from .. import db
from  app.models import User, Role, Ministry, Events, Donation

# admin dashboard
@admin.route('/dashboard')
def dashboard():
    return render_template('admin/dashboard.html')

@admin.route('/user_management')
def user_management():
    # query all users from database if role id is 1
    users_data = User.query.filter_by(role_id=1).all()

    
    return render_template('admin/user_management.html', users_data=users_data)

@admin.route('/event_management', methods=['GET', 'POST'])
def event_management():
    # CRUD operations for events
    if request.method == 'POST':
        if 'create' in request.form:
            title = request.form['title']
            description = request.form['description']
            new_event = Events(title=title, description=description)
            db.session.add(new_event)
            db.session.commit()
            flash('Event has been created successfully', 'success')
            return redirect(url_for('admin.event_management'))
        
        elif 'update' in request.form:
            event_id = request.form['event_id']
            event = Events.query.get(event_id)
            event.title = request.form['title']
            event.description = request.form['description']
            db.session.commit()
            flash('Event has been updated successfully', 'success')
            return redirect(url_for('admin.event_management'))
        
        elif 'delete' in request.form:
            event_id = request.form['event_id']
            event = Events.query.get(event_id)
            db.session.delete(event)
            db.session.commit()
            flash('Event has been deleted successfully', 'success')
            return redirect(url_for('admin.event_management'))
    return render_template('admin/event_management.html')

@admin.route('/donation_management', methods=['GET', 'POST'])
def donation_management():
    # CRUD operations for donations
    if request.method == 'POST':
        if 'create' in request.form:
            name = request.form['name']
            description = request.form['description']
            new_donation = Donation(name=name, description=description)
            db.session.add(new_donation)
            db.session.commit()
            flash('Donation has been created successfully', 'success')
            return redirect(url_for('admin.donation_management'))
        
        elif 'update' in request.form:
            donation_id = request.form['donation_id']
            donation = Donation.query.get(donation_id)
            donation.name = request.form['name']
            donation.description = request.form['description']
            db.session.commit()
            flash('Donation has been updated successfully', 'success')
            return redirect(url_for('admin.donation_management'))
        
        elif 'delete' in request.form:
            donation_id = request.form['donation_id']
            donation = Donation.query.get(donation_id)
            db.session.delete(donation)
            db.session.commit()
            flash('Donation has been deleted successfully', 'success')
            return redirect(url_for('admin.donation_management'))
    return render_template('admin/donation_management.html')

@admin.route('/ministries', methods=['GET', 'POST'])
def ministries():
    if request.method == 'POST':
        if 'create' in request.form:
            name = request.form['name']
            description = request.form['description']
            new_ministry = Ministry(name=name, description=description)
            db.session.add(new_ministry)
            db.session.commit()
            flash('Ministry has been created successfully', 'success')
            return redirect(url_for('admin.ministries'))
    
        elif 'update' in request.form:
            ministry_id =request.form['ministry_id']
            ministry = Ministry.query.get(ministry_id)
            ministry.name = request.form['name']
            ministry.description = request.form['description']
            db.session.commit()
            flash('Ministry has been updated successfully', 'success')
            return redirect(url_for('admin.ministries'))
        
        elif 'delete' in request.form:
            ministry_id = request.form['ministry_id']
            ministry = Ministry.query.get(ministry_id)
            db.session.delete(ministry)
            db.session.commit()
            flash('Ministry has been deleted successfully', 'success')
            return redirect(url_for('admin.ministries'))
    ministries = Ministry.query.all()
    return render_template('admin/ministries.html', ministries=ministries)

@admin.route('edit_user')
def edit_user(id):
    user = User.query.get_or_404(id)
    return render_template('admin/edit_user.html', user=user)


# delete user from the database
@admin.route('/delete_user/<int:id>')
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('User has been deleted successfully')
    return redirect(url_for('admin.user_management'))