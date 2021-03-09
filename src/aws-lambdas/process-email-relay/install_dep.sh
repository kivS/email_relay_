 echo "Going to pip install: [ $1 ]"
 python -m pip install  --target=./external_dependencies $1

 echo "Freezing dependencies"
 python -m pip freeze --path ./external_dependencies > requirements.txt