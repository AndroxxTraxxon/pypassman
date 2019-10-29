read -p "Press [Enter] key to start continue..."
python -m pip install -r setup-requirements.txt
python -m virtualenv __venv__
__venv__\\Scripts\\activate.bat
python -m pip install -r requirements.txt # install dependencies inside the venv
python setup.py
deactivate
read -p "Press [Enter] key to start continue..."