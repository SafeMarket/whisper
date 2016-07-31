module.exports = function gruntfile(grunt) {
  grunt.loadNpmTasks('grunt-contrib-watch')
  grunt.loadNpmTasks('grunt-mocha-test')

  grunt.initConfig({
    watch: {
      tests: {
        files: ['lib/*','test/*'],
        tasks: ['mochaTest']
      },
    },
    mochaTest: {
      test: {
        src: ['test/**/*.js']
      }
    },
  })

  grunt.registerTask('init', [
    'mochaTest',
    'watch'
  ])
}
