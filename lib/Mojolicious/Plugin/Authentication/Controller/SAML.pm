package Mojolicious::Plugin::Authentication::Controller::SAML;
use v5.26;
use warnings;

# ABSTRACT: 

use Mojo::Base 'Mojolicious::Controller';

use Mojo::Parameters;
use Syntax::Keyword::Try;

use experimental qw(signatures);

sub redirect($self) {
  my $idp = Net::SAML2::IdP->new_from_url(url => $args->{metadata_url});

  my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
    issuer        => $args->{entity_id},
    destination   => $idp->sso_url($IDP_DESTINATION),
    nameid_format => $idp->format($LOGIN_NAMEID_FORMAT),
  );

  # Seems REALLY unlikely this will fail, but it's really important that we have/store our ID
  die $ERROR_SAML_AUTH_REQUEST_FAILED unless $authnreq && $authnreq->id;

  # We need to hang on to this for the validation when /saml gets POSTed
  $self->cookie($AUTH_COOKIE_NAME => $authnreq->id, {expires => time + 10 * ONE_MINUTE, path => q{/}});

  my $redirect = Net::SAML2::Binding::Redirect->new(
    key   => $args->{sp_signing_key},
    cert  => $idp->cert($IDP_CERT_TYPE),
    param => $SAML_REDIRECT_PARAM,
    url   => $idp->sso_url($IDP_DESTINATION),
  );

  # Ok.  Now we tell the browser to redirect to the login page at our idp
  my $url = $redirect->sign($authnreq->as_xml);
  $self = $self->redirect_to($url);
}

sub login($self) {
  my $saml_response = $self->param($SAML_RESPONSE_PARAM);

  # This next section will verify that Duo (our IdP) signed the response
  # ret will look like: 'O=Duo Security, CN=DIAWQZK73N3X4N1SZNHI (verified)'

  my $post = Net::SAML2::Binding::POST->new();
  my $ret  = $post->handle_response($saml_response);

  # This needs to be checked but not sure the best way to handle from a UX perspective.  Really just making
  # sure that everything was signed ok.  Either a cert's expired or some weird attack.  Seems VERY UNLIKELY
  die $ERROR_SAML_INVALID_RESPONSE unless $ret;

  # Ok signatures are good, now we need to validate the assertion.

  # If we're being asked to validate an assertion, we need to have the authid which was set MINUTES ago...
  # Short of a session cookies problem, should never happen...
  die $ERROR_SAML_AUTH_COOKIE_MISSING unless $self->cookie($AUTH_COOKIE_NAME);

  my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(xml => b64_decode($saml_response));
  my $valid     = $assertion->valid($args->{entity_id}, $self->cookie($AUTH_COOKIE_NAME));

  # Destry the auth cookie immediately now that we no longer need it (switching to session storage)
  $self->cookie($AUTH_COOKIE_NAME => q{}, {expires => 1});

  # This needs to be checked but not sure the best way to handle from a UX perspective.  Either a MITM/replay
  # issue or **MAYBE** a clock sync issues between us and the idp.  Seems VERY UNLIKELY
  die $ERROR_SAML_INVALID_ASSERTION unless $valid;
  my $username = $assertion->attributes->{username}->[0];

  my $sub = {
    username      => $username,
    email_address => $assertion->nameid,
    displayname   => $assertion->attributes->{displayname}->[0],
    firstname     => $assertion->attributes->{firstname}->[0],
    lastname      => $assertion->attributes->{lastname}->[0],
  };

  my $user = $self->app->find_and_update_login_user($sub);
  $self->session(
    uid   => $user->id,
    sub   => $sub,
    roles => $assertion->attributes->{access_control},
    ctx   => {
      saml_session => $assertion->session,
    }
  );

  $self->redirect_to($AUTH_SUCCESS_PATH);
}

sub logout($self) {
  my $idp = Net::SAML2::IdP->new_from_url(url => $args->{metadata_url});

  my $logoutrequest = Net::SAML2::Protocol::LogoutRequest->new(
    issuer        => $args->{entity_id},
    nameid_format => $LOGOUT_NAMEID_FORMAT,
    destination   => $args->{slo_url},
    nameid        => $self->session('sub')->{email_address},
    session       => $self->session('ctx')->{saml_session}
  );

  my $redirect = Net::SAML2::Binding::Redirect->new(
    key   => $args->{sp_signing_key},
    cert  => $idp->cert($IDP_CERT_TYPE),
    param => $SAML_REDIRECT_PARAM,
    url   => $args->{slo_url}
  );

  $self->session({uid => undef, sub => undef, roles => undef, expires => true});

  # Ok.  Now we tell the browser to redirect to the logout page at our idp
  my $url = $redirect->sign($logoutrequest->as_xml);
  $self = $self->redirect_to($url);
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