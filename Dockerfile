FROM jruby:9.1

# throw errors if Gemfile has been modified since Gemfile.lock
RUN bundle config --global frozen 1

ADD . /usr/src/app
WORKDIR /usr/src/app

COPY Gemfile Gemfile.lock ./
RUN bundle install
RUN echo 'CLASSPATH=/usr/local/openjdk-8/lib' > /etc/environment
RUN wget http://archive.apache.org/dist/logging/log4j/1.2.17/log4j-1.2.17.jar -O /usr/local/openjdk-8/lib/log4j-1.2.17.jar
#RUN CLASSPATH=/usr/loca/openjdk-8/lib bundle exec rspec
#RUN gem build logstash-input-varnishncsa.gemspec
