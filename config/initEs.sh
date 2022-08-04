mkdir "data"
mkdir "logs"
docker run --restart=always --ulimit nofile=65536:65536 \
  -p 9200:9200 -p 9300:9300 -d --name es1 \
  -v $PWD/logs:/usr/share/elasticsearch/logs \
  -v $PWD/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml \
  -v $PWD/config/jvm.options:/usr/share/elasticsearch/config/jvm.options  \
  -v $PWD/data:/usr/share/elasticsearch/data  hktalent/elasticsearch:7.16.2
echo "Wait for es to start before running the following script"
docker logs -f es1
echo "Wait for es to start before running the following script"
./config/CreateEs.sh nmap
./config/CreateEs.sh naabu
./config/CreateEs.sh httpx
./config/CreateEs.sh nuclei
./config/CreateEs.sh scan4all
./config/CreateEs.sh hydra
./config/CreateEs.sh subfinder
docker logs -f es1
