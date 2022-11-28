# Prithiviraj Eswaramoorthy
# 1001860633

#References:
#https://www.sqlitetutorial.net/sqlite-distinct/
#https://stackoverflow.com/questions/62606040/display-python-list-as-table-in-html
#https://stackoverflow.com/questions/34122949/working-outside-of-application-context-flask
#https://github.com/hilalahmad32/user-management-system-in-flask
#https://github.com/arpanneupane19/Python-Flask-Authentication-Tutorial
#https://github.com/PrettyPrinted/youtube_video_code/tree/master/2022/01/22/Uploading%20and%20Returning%20Files%20With%20a%20Database%20in%20Flask
#https://www.youtube.com/watch?v=71EU8gnZqZQ&ab_channel=ArpanNeupane
#https://www.youtube.com/watch?v=rQ_sHd2_Ppk&list=PLKbhw6n2iYKieyy9hhLjLMpD9nbOnCVmo&index=8&ab_channel=projectworld
#https://www.youtube.com/watch?v=bb1A2RQgDRs&list=PLKbhw6n2iYKieyy9hhLjLMpD9nbOnCVmo&index=7&ab_channel=projectworld
#https://www.youtube.com/watch?v=ZMwrBzyZgto&ab_channel=THESHOW
#https://flask.palletsprojects.com/en/1.1.x/patterns/fileuploads/
#https://www.programcreek.com/python/example/99651/flask_login.current_user.username
#https://www.youtube.com/watch?v=dP-2NVUgh50&t=35s&ab_channel=RedEyedCoderClub
#https://tutorial101.blogspot.com/2021/04/python-flask-upload-and-display-image.html


from flask import Flask, render_template, url_for, redirect, request, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from flask_session import Session
import sqlite3
from io import BytesIO
from base64 import b64encode

ALLOWED_EXTENSIONS_IMAGES = {'png', 'jpg', 'jpeg'}
ALLOWED_EXTENSIONS_TXT = {'png', 'jpg', 'jpeg'}
ALLOWED_EXTENSIONS_VIDEO = {'png', 'jpg', 'jpeg'}
ALLOWED_EXTENSIONS_AUDIO = {'png', 'jpg', 'jpeg'}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'prithivi123'

@app.before_first_request
def create_tables():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(20), nullable=False)
    lastname = db.Column(db.String(20), nullable=False)
    #usergroup = db.Column(db.String(20), nullable=False, unique=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    status=db.Column(db.Integer,default=0, nullable=False)

class Group(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String(20), nullable=False)
    groupdescription = db.Column(db.String(50), nullable=False)

class GroupUsers(db.Model, UserMixin):
    groupname = db.Column(db.String(20), nullable=False, primary_key=True)
    username = db.Column(db.String(20), nullable=False, primary_key=True)

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(50))
    data = db.Column(db.LargeBinary)
    groupname = db.Column(db.String(50))
    

class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    firstname = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Firstname"})
    lastname = StringField(validators=[
                           InputRequired()], render_kw={"placeholder": "Lastname"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

class CreateGroup(FlaskForm):
    groupname = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "groupname"})
    groupdescription = StringField(validators=[
                           InputRequired(), Length(min=4, max=50)], render_kw={"placeholder": "groupdescription"})
    

    submit = SubmitField('CreateGroup')

class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login',  methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data) and user.status == 1:
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register',  methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8 ')
        new_user = User(username=form.username.data, password=hashed_password, firstname=form.firstname.data,lastname=form.lastname.data)
        print("eee",new_user.id)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)

@app.route('/createGroup',  methods=['GET', 'POST'])
def createGroup():
    form = CreateGroup()
    
    if form.validate_on_submit():
        new_group = Group(groupname=form.groupname.data, groupdescription=form.groupdescription.data)
        group_add = GroupUsers(groupname=form.groupname.data, username=current_user.username)
        db.session.add(new_group)
        db.session.add(group_add)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template('createGroup.html',form=form)

#-----------------------


# create admin Class
class Admin(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(255), nullable=False)
    password=db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'Admin("{self.username}","{self.id}")'

# insert admin data one time only one time insert this data
# latter will check the condition
#with app.app_context():
    #admin=Admin(username='admin123',password=bcrypt.generate_password_hash('admin123',10))
    #db.session.add(admin)
    #db.session.commit()

@app.route('/admin/',methods=["POST","GET"])
def adminIndex():
    # chect the request is post or not
    if request.method == 'POST':
        # get the value of field
        username = request.form.get('username')
        password = request.form.get('password')
        # check the value is not empty
        if username=="" and password=="":
            flash('Please fill all the field','danger')
            return redirect('/admin/')
        else:
            # login admin by username 
            admins=Admin().query.filter_by(username=username).first()
            if admins and bcrypt.check_password_hash(admins.password,password):
                session['admin_id']=admins.id
                session['admin_name']=admins.username
                flash('Login Successfully','success')
                return redirect('/admin/dashboard')
            else:
                flash('Invalid Email and Password','danger')
                return redirect('/admin/')
    else:
        return render_template('admin/index.html',title="Admin Login")

# admin Dashboard
@app.route('/admin/dashboard')
def adminDashboard():
    if not session.get('admin_id'):
        return redirect('/admin/')
    totalUser=User.query.count()
    totalApprove=User.query.filter_by(status=1).count()
    NotTotalApprove=User.query.filter_by(status=0).count()
    return render_template('admin/dashboard.html',title="Admin Dashboard",totalUser=totalUser,totalApprove=totalApprove,NotTotalApprove=NotTotalApprove)

# admin get all user 
@app.route('/admin/get-all-user', methods=["POST","GET"])
def adminGetAllUser():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if request.method== "POST":
        search=request.form.get('search')
        users=User.query.filter(User.username.like('%'+search+'%')).all()
        return render_template('admin/all-user.html',title='Approve User',users=users)
    else:
        users=User.query.all()
        return render_template('admin/all-user.html',title='Approve User',users=users)

@app.route('/user/fetch-all-groups', methods=["POST","GET"])
def fetchAllgroups():
    # if not session.get('admin_id'):
    #     return redirect('/dashboard')
    if request.method== "POST":
        groups=Group.query.all()
        join_group =request.form.get('join_group')
        new_grp_user = GroupUsers(groupname=join_group, username=current_user.username)
        db.session.add(new_grp_user)
        db.session.commit()
        return render_template('all-groups.html',groups=groups)
        #return redirect(url_for('login'))
        #------
        #------
    else:
        groups=Group.query.all()
        return render_template('all-groups.html',groups=groups)

@app.route('/user/viewmygroups', methods=["POST","GET"])
def viewmygroups():
    form = uploadForm()
    groups=GroupUsers.query.filter(GroupUsers.username.like('%'+current_user.username+'%')).all()
    return render_template('mygroups.html',groups=groups, form=form)

@app.route('/user/groupfunctions', methods=["POST","GET"])
def grpfunc():
    if request.method == 'GET':
        return render_template('groupfunctions.html')
    return render_template('groupfunctions.html')

@app.route('/user/view-grp-users', methods=["POST","GET"])
def viewgroupusers():
    # if not session.get('admin_id'):
    #     return redirect('/dashboard')
    if request.method== "POST":
        search=request.form.get('search')
        groups=GroupUsers.query.filter(GroupUsers.groupname.like('%'+search+'%')).all()
        return render_template('grp-users.html',groups=groups)
    else:
        sqliteConnection = sqlite3.connect('/Users/prithivi/Desktop/Secure Project/Proj/instance/database.db')
        #sqliteConnection = sqlite3.connect('../instance/database.db')
        cursor = sqliteConnection.cursor()
        sqlite_select_query = """SELECT distinct groupname from group_users"""
        cursor.execute(sqlite_select_query)
        records = cursor.fetchall()
        return render_template('grp-users.html',records=records)



@app.route('/admin/approve-user/<int:id>')
def adminApprove(id):
    if not session.get('admin_id'):
        return redirect('/admin/')
    User().query.filter_by(id=id).update(dict(status=1))
    db.session.commit()
    flash('Approve Successfully','success')
    return redirect('/admin/get-all-user')

# admin logout
@app.route('/admin/logout')
def adminLogout():
    if not session.get('admin_id'):
        return redirect('/admin/')
    if session.get('admin_id'):
        session['admin_id']=None
        session['admin_name']=None
        return redirect('/')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMAGES



class uploadForm(FlaskForm):
    groupname = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "groupname"})


#upload 
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form = uploadForm()
    gname = form.groupname.data
    if request.method == 'POST':
        file = request.files['file']
        user = GroupUsers.query.filter_by(groupname=gname).first()
        fname = GroupUsers.query.filter(GroupUsers.username.like('%'+current_user.username+'%')).all()
        print(user.username)
        print(current_user.username)
        if file and allowed_file(file.filename) and user.username == current_user.username:
            upload = Upload(filename=file.filename, data=file.read(), groupname=gname)
            db.session.add(upload)
            db.session.commit()

            return f'Uploaded: {file.filename}'
    return render_template('upload.html', form=form)
    return redirect('/dash')

@app.route('/files', methods=['GET','POST'])
def files():
    form = uploadForm()
    gname = form.groupname.data
    user = GroupUsers.query.filter_by(groupname=gname).first()
    print(user)
    print(gname)
    if user.username == current_user.username:
        items = Upload.query.filter(Upload.groupname.like('%'+gname+'%')).all()
    return render_template('files.html',items = items,form=form)


@app.route('/download/<int:id>', methods=['GET'])
def download(id):
    
    upload = Upload.query.filter_by(id=id).first()
    return send_file(BytesIO(upload.data), download_name=upload.filename, as_attachment=True)

@app.route('/viewimages', methods=['GET'])
def show():
    dbpic = Upload.query.filter_by(Upload.id).all()
    for i in dbpic: 
        picture = b64encode(i.data).decode("utf-8")
    return render_template("viewimages.html", dbpic=dbpic, picture=picture)


if __name__ == "__main__":
    app.run(debug=True)