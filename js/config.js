module.exports = {
  db : {
    url : 'mongodb://localhost/dns',
    collection : 'dns',
    filesCollection : 'files' // used to make sure no duplicates
  },
  cacheSize : 1000
};
