# Generated from Makefile.PL using makefilepl2cpanfile

requires 'perl', '5.008';

requires 'Carp';
requires 'ExtUtils::MakeMaker', '6.64';
requires 'HTML::Entities';
requires 'HTML::Parser';
requires 'Params::Get';
requires 'Params::Validate::Strict';

on 'test' => sub {
	requires 'Test::Compile';
	requires 'Test::DescribeMe';
	requires 'Test::Most';
	requires 'Test::Needs';
	requires 'Test::Warnings';
};

on 'develop' => sub {
	requires 'Devel::Cover';
	requires 'Perl::Critic';
	requires 'Test::Pod';
	requires 'Test::Pod::Coverage';
};
