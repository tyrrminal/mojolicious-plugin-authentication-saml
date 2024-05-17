package Mojolicious::Plugin::Concert::Base::Auth::SAML;
use v5.26;
use warnings;

# ABSTRACT: Implementation for Concert SAML authentication/authorization and session-handling

use builtin qw(true);

use Mojo::Base 'Mojolicious::Plugin';

use List::Compare;
use Mojo::Util qw(64_decode);
use Net::SAML2::IdP;
use Net::SAML2::Protocol::Assertion;
use Net::SAML2::Protocol::AuthnRequest;
use Net::SAML2::Protocol::LogoutRequest;
use Net::SAML2::Binding::Redirect;
use Net::SAML2::Binding::POST;
use Readonly;
use Time::Seconds;

use experimental qw(signatures builtin);

Readonly::Scalar my $DEFAULT_BASE_PATH  => q{/auth};
Readonly::Scalar my $SAML_LOGIN_PATH    => q{/login};
Readonly::Scalar my $SAML_LOGOUT_PATH   => q{/logout};
Readonly::Scalar my $SAML_RESPONSE_PATH => q{/};

Readonly::Scalar my $AUTH_COOKIE_NAME  => q{authid};
Readonly::Scalar my $AUTH_SUCCESS_PATH => q{/login};

Readonly::Scalar my $IDP_DESTINATION      => q{urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect};
Readonly::Scalar my $LOGOUT_NAMEID_FORMAT => q{urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress};
Readonly::Scalar my $IDP_CERT_TYPE        => q{signing};
Readonly::Scalar my $LOGIN_NAMEID_FORMAT  => q{persistent};
Readonly::Scalar my $SAML_REDIRECT_PARAM  => q{SAMLRequest};
Readonly::Scalar my $SAML_RESPONSE_PARAM  => q{SAMLResponse};

Readonly::Scalar my $ERROR_SAML_AUTH_REQUEST_FAILED => q{SAML2 AuthnRequest failed};
Readonly::Scalar my $ERROR_SAML_INVALID_RESPONSE    => q{Invalid SAML response received};
Readonly::Scalar my $ERROR_SAML_AUTH_COOKIE_MISSING => q{SAML auth cookie not found};
Readonly::Scalar my $ERROR_SAML_INVALID_ASSERTION   => q{Invalid SAML assertion received};

sub register ($module, $app, $args) {
  $app->sessions->default_expiration($args->{default_session_expiration} // ONE_DAY);
  my $roles = $args->{roles};

  my $base_path = $args->{base_path} // $DEFAULT_BASE_PATH;
  my $auth      = $app->routes->any($base_path);


  $app->helper(
    current_user => sub ($self) {
      my $sub = $self->session('sub') // {};
      if (my $username = $sub->{username}) {
        if (my $user = $app->model('User')->find({username => $username})) {
          return $user;
        }
      }
      return;
    }
  );
  $app->helper(
    current_user_roles => sub ($self) {
   # The config hashref is a set of keys (app roles) pointing to arrayrefs (hierarchical auth group paths).
   # For SAML, we match the last item in that arrayref (lowercased) to the SP 'access_control' response (which we stored in session)
      return [
        grep {List::Compare->new('-u', $self->session('roles') // [], [lc($roles->{$_}->[-1])])->get_intersection()}
          keys($roles->%*)
      ];
    }
  );

  $app->helper(
    is_role => sub ($self, @roles) {
      my $lc = List::Compare->new('-u', $self->current_user_roles, [@roles]);
      return $lc->get_intersection() > 0;
    }
  );

  $app->helper(
    is_admin => sub ($self) {
      return $self->is_role($args->{admin_roles}->@*);
    }
  );

  if($conf{})
}

=head1 AUTHOR

Mark Tyrrell C<< <mark@tyrrminal.dev> >>

=head1 LICENSE

Copyright (c) 2024 Mark Tyrrell

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

=cut

1;

__END__