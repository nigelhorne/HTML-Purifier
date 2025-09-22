use strict;
use warnings;
use ExtUtils::MakeMaker;

my $dist = {
	COMPRESS => 'gzip -9f',	# Compress tarball using gzip
	SUFFIX => 'gz',	# File suffix for tarball
};

if($^O eq 'darwin') {
	$dist->{'TAR'} = 'gtar';
}

WriteMakefile(
	ABSTRACT_FROM => 'lib/HTML/Sanitizer.pm',
	AUTHOR => 'Nigel Horne <njh@nigelhorne.com>',
	NAME => 'HTML::Sanitizer',
	VERSION_FROM => 'lib/HTML/Sanitizer.pm', # finds $VERSION in the module
	((defined($ExtUtils::MakeMaker::VERSION) && ($ExtUtils::MakeMaker::VERSION >= 6.3002))
		? ('LICENSE'=> 'GPL')
		: ()),
	PREREQ_PM => {
		'ExtUtils::MakeMaker' => 6.64,	# Minimum version for TEST_REQUIRES
		'HTML::Parser' => 0,
		'HTML::Entities' => 0,
		'Carp' => 0,
	},
	META_MERGE => {
		resources => {
			repository => {
				type => 'git',
				url => 'https://github.com/nigelhorne/HTML-Sanitizer.git',
				web => 'https://github.com/nigelhorne/HTML-Sanitizer',
			},
			bugtracker => {
				web => 'https://github.com/nigelhorne/HTML-Sanitizer/issues',
			},
		},
	},
	TEST_REQUIRES => {
		'Test::Compile' => 0,
		'Test::DescribeMe' => 0,
		'Test::Most' => 0,
		'Test::Needs' => 0,
		'Test::Warnings' => 0
	}, dist => $dist,
	clean => { FILES => 'HTML-Sanitizer-*' },	# Clean up distribution files
);
