#!/usr/bin/perl

# sig2dot v0.17 (c) Darxus@ChaosReigns.com, released under the GPL
# Download from: http://www.chaosreigns.com/debian-keyring
#
# Parses the (gpg) debian-keyring 
# (http://www.debian.org/Packages/unstable/misc/debian-keyring.html) to a format
# suitable for use by dot or neato (package name graphviz,
# http://www.research.att.com/sw/tools/graphviz/) like so:
#
# gpg --list-sigs --keyring /usr/share/keyrings/debian-keyring.gpg | ./sig2dot.pl > debian-keyring.dot
# neato -Tps debian-keyring.dot > debian-keyring.neato.dot.ps
# dot -Tps debian-keyring.dot > debian-keyring.dot.dot.ps
#
# v0.9 2000-09-14 19:20  strip trailing whitespace from $id more cleanly
# v0.10 2000-09-14 19:33 skip revoked keys at the request of Peter Palfrader <ppalfrad@cosy.sbg.ac.at>
# v0.11 Nov 22 21:38     use ID for node name instead of username for uniqueness
# v0.12 Dec 15 16:20 use names instead of IDs again in stats.html
# v0.13 Jun 19 03:15 red is proportional to signatures
# v0.14 Jun 19 03:25 blue is proportional to other keys signed
# v0.15 Jun 20 17:16 fixed blue, green is proportional to ratio
# v0.16 Jun 20 18:55 uniqed %signedby
# v0.17 Jan 10 19:10 Use overlap=scale instead of fixed edge lengths.  Requires new version of graphviz.


$chartchar = "*";

while ($line = <STDIN>)
{
  chomp $line;
  if ($line =~ m#([^ ]+) +([^ ]+) +[^ ]+ +([^<]+)#)
  {
    $type = $1;
    $id = $2;
    $name = $3;
    # strip trailing whitespace more cleanly:
    $name =~ s/\s+$//g;

    if ($type eq "pub")
    {
      $id = (split('/',$id))[1];
      $owner = $id; 
    } 

    $name{$id} = $name;

    # skip revoked keys 
    next if ($owner eq '[revoked]');

    if ($type eq "sig" and $id ne $owner and $name ne '[User id not found]')
    {
      push (@{$sigs{$owner}},$id);
      push (@{$signedby{$id}},$owner);
      push (@names,$id,$owner);
    }
  } else {
    print STDERR "Skipping: $line\n";
  }
}

print "digraph \"debian-keyring\" {\noverlap=scale\nsplines=true\nsep=.1\n";

undef %saw;
@saw{@names} = ();
@names = keys %saw;
undef %saw;

for $owner (sort {$sigs{$a} <=> $sigs{$b}} keys %sigs)
{
  undef %saw;
  @saw{@{$sigs{$owner}}} = ();
  @{$sigs{$owner}} = keys %saw;
  undef %saw;
  undef %saw;
  @saw{@{$signedby{$owner}}} = ();
  @{$signedby{$owner}} = keys %saw;
  undef %saw;

  $sigcount{$owner} = scalar(@{$sigs{$owner}});
  if ($sigcount{$owner} > $maxsigcount)
  {
    $maxsigcount = $sigcount{$owner};
  }

  $signedbycount{$owner} = scalar(@{$signedby{$owner}});
  if ($signedbycount{$owner} > $maxsignedbycount)
  {
    $maxsignedbycount = $signedbycount{$owner};
  }
  if ($signedbycount{$owner} / $sigcount{$owner} > $maxratio)
  {
    $maxratio = $signedbycount{$owner} / $sigcount{$owner};
  }
}
print "//$maxratio\n";

open (STATS,">stats.html");
print STATS "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">\n<html><head><title>Keyring Statistics</title></head><body><table border=1>\n";

for $owner (sort {$sigcount{$b} <=> $sigcount{$a}} keys %sigs)
{
  print STATS "<tr><td>$name{$owner}<td>$sigcount{$owner}<td><img src=\"/images/pipe0.jpg\" height=15 width=",$sigcount{$owner} * 20," alt=\"". $chartchar x $sigcount{$owner} ."\">\n";
}

print STATS "</table></body></html>\n";
close STATS;

print "node [style=filled]\n";
for $id (@names)
{
  $red = $sigcount{$id} / $maxsigcount;
  #$green = .25;
  $green = $signedbycount{$id} / $sigcount{$id} / $maxratio * .75;
  $blue = $signedbycount{$id} / $maxsignedbycount;
  ($hue,$saturation,$value) = rgb2hsv($red,$green,$blue);
  #print "//$red,$green,$blue\n";
  print "//$sigcount{$id} $signedbycount{$id} $red,$green,$blue\n";
  print "\"$id\" [color=\"$hue,$saturation,$value\",label=\"$name{$id}\"]\n";
}
#print "node [style=solid]\n";

for $owner (sort keys %sigs)
{
  for $id (@{$sigs{$owner}})
  {
    print "\"$id\" -> \"$owner\"\n";
  }
}

print "}\n";

#  Converts rgb to hsv.  All numbers are within range 0 to 1
#  from http://twiki.org/cgi-bin/view/Codev/WebMap
sub rgb2hsv {
    my ($r, $g ,$b) = @_;
    my $max = maxof($r, maxof($g, $b));
    my $min = minof($r, minof($g, $b));
    $v = $max;

    if ($max > 0.0) {
        $s = ($max - $min) / $max;
    } else {
        $s = 0;
    }
    if ($s > 0.0) {
        my ($rc, $gc, $bc, $diff);
            $diff = $max - $min;
        $rc = ($max - $r) / $diff;
        $gc = ($max - $g) / $diff;
        $bc = ($max - $b) / $diff;
        if ($r == $max) {
            $h = ($bc - $gc) / 6.0;
        } elsif ($g == $max) {
            $h = (2.0 + $rc - $bc) / 6.0;
        } else {
            $h = (4.0 + $gc - $rc) / 6.0;
        }
    } else {
       $h = 0.0;
    }
    if ($h < 0.0) {
       $h += 1.0;
    }
    return ($h, $s, $v);
}
sub maxof {
   my ($a, $b) = @_;

   return $a>$b?$a:$b;
}
sub minof {
   my ($a, $b) = @_;

   return $a<$b?$a:$b;
}


