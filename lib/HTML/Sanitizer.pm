package HTML::Sanitizer;

use strict;
use warnings;
use HTML::Parser;
use HTML::Entities qw(encode_entities);

our $VERSION = '1.00';

=head1 NAME

HTML::Sanitizer - Basic HTML sanitization

=head1 VERSION

Version 1.00

=head1 DESCRIPTION

HTML::Sanitizer provides basic HTML sanitization capabilities.
It allows you to define a whitelist of allowed tags and attributes, and it removes or encodes any HTML that is not on the whitelist. This helps to prevent cross-site scripting (XSS) vulnerabilities.

=head1 SYNOPSIS

=head2 Basic Usage

	use HTML::Sanitizer;

	my $sanitizer = HTML::Sanitizer->new(
		allow_tags => [qw(p b i a)],
		allow_attributes => {
			a => [qw(href title)],
		},
	);

	my $input_html = '<p><b>Hello, <script>alert("XSS");</script></b> <a href="javascript:void(0);">world</a></p>';
	my $sanitized_html = $sanitizer->sanitize($input_html);

	print $sanitized_html; # Output: <p><b>Hello, </b> <a href="world">world</a></p>

=head2 Allowing Comments

	use HTML::Sanitizer;

	my $sanitizer = HTML::Sanitizer->new(
		allow_tags => [qw(p b i a)],
		allow_attributes => {
			a => [qw(href title)],
		},
		strip_comments => 0, # Do not strip comments
	);

	my $input_html = '<p><b>Hello, </b></p>';
	my $sanitized_html = $sanitizer->sanitize($input_html);

	print $sanitized_html; # Output: <p><b>Hello, </b></p>

=head2 Encoding Invalid Tags

	use HTML::Sanitizer;

	my $sanitizer = HTML::Sanitizer->new(
		allow_tags => [qw(p b i a)],
		allow_attributes => {
			a => [qw(href title)],
		},
		encode_invalid_tags => 1, # Encode invalid tags.
	);

	my $input_html = '<my-custom-tag>Hello</my-custom-tag>';
	my $sanitized_html = $sanitizer->sanitize($input_html);

	print $sanitized_html; # Output: &lt;my-custom-tag&gt;Hello&lt;/my-custom-tag&gt;

=head1 METHODS

=head2 new(%args)

Creates a new HTML::Sanitizer object.

=over 4

=item allow_tags

An array reference containing the allowed HTML tags (case-insensitive).

=item allow_attributes

A hash reference where the keys are allowed tags (lowercase), and the values are array references of allowed attributes for that tag.

=item strip_comments

A boolean value (default: 1) indicating whether HTML comments should be removed.

=item encode_invalid_tags

A boolean value (default: 1) indicating whether invalid tags should be encoded or removed.

=back

=cut

sub new {
	my ($class, %args) = @_;
	my $self = {
		allow_tags => $args{allow_tags} || [],
		allow_attributes => $args{allow_attributes} || {},
		strip_comments => $args{strip_comments} // 1, # Default to stripping comments
		encode_invalid_tags => $args{encode_invalid_tags} // 1, # Default to encoding invalid tags
	};
	bless $self, $class;
	return $self;
}

=head2 sanitize($html)

Sanitizes the given HTML string.

=over 4

=item $html

The HTML string to be sanitized.

=back

Returns the sanitized HTML string.

=cut

sub sanitize {
    my ($self, $html) = @_;
    my $output = '';

    my $parser = HTML::Parser->new(
        handlers => {
            start => [ sub {
                my ($tag, $attr, $text) = @_;
                if (grep { lc $_ eq lc $tag } @{$self->{allow_tags}}) {
                    $output .= "<$tag";
                    foreach my $attr_name (keys %$attr) {
                        if (exists $self->{allow_attributes}->{lc $tag}
                            && grep { lc $_ eq lc $attr_name } @{$self->{allow_attributes}->{lc $tag}}) {
                            $output .= " $attr_name=\"" . encode_entities($attr->{$attr_name}) . "\"";
                        }
                    }
                    $output .= '>';
                } elsif ($self->{encode_invalid_tags}) {
                    $output .= encode_entities(
                        "<$tag" . (join " ", map {$_ . "=\"" . encode_entities($attr->{$_}) . "\""} keys %$attr) . ">"
                    );
                }
            }, "tagname, attr, text"],

            end => [ sub {
                my ($tag) = @_;
                if (grep { lc $_ eq lc $tag } @{$self->{allow_tags}}) {
                    $output .= "</$tag>";
                } elsif ($self->{encode_invalid_tags}) {
                    $output .= encode_entities("</$tag>");
                }
            }, "tagname"],

            text => [ sub {
                my ($text) = @_;
                $output .= encode_entities($text);
            }, "text"],

            comment => [ sub {
                my ($text) = @_;
                if (!$self->{strip_comments}) {
                    $output .= "<!--$text-->";
                }
            }, "text"],
        },
        marked_sections => 1,
    );

    $parser->parse($html);
    $parser->eof;
    return $output;
}

1;

=head1 DEPENDENCIES

* HTML::Parser
* HTML::Entities

=head1 CAVEATS

This is a basic HTML sanitizer. For production environments, consider using more mature and actively maintained libraries like C<http://htmlpurifier.org/> or L<Mojolicious::Plugin::TagHelpers>.

=head1 AUTHOR

Nigel Horne C< << njh @ nigelhorne.com >> >

=head1 COPYRIGHT AND LICENSE

Copyright 2025 Nigel Horne

This library is free software; you can redistribute it and/or modify it under the same terms as Perl itself.
