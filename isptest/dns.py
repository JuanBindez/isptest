import time
import dns.resolver
import dns.reversename


class DNS:
  def __init__(
      self, nameservers: list[str] = None, timeout: float = 2.0
  ) -> None:
    self.resolver = dns.resolver.Resolver(configure=False)
    if nameservers:
      self.resolver.nameservers = nameservers
    self.resolver.lifetime = timeout

  def test_latency(self, domain: str = 'google.com') -> float | None:
    
    inicio = time.time()
    try:
      self.resolver.resolve(domain, 'A')
      return round((time.time() - inicio) * 1000, 2)
    except Exception:
      return None

  def query_record(
      self, domain: str, rtype: str = 'A'
  ) -> list[str] | dict[str, str]:
    
    try:
      resposta = self.resolver.resolve(domain, rtype)
      if rtype == 'MX':
        return [
            f'{r.preference} {r.exchange.to_text()}'
            for r in resposta  # type: ignore
        ]
      return [r.to_text() for r in resposta]
    except (dns.resolver.Timeout, dns.resolver.NXDOMAIN, Exception) as e:
      return {'error': str(type(e).__name__), 'details': str(e)}

  def test_tcp_support(self, domain: str = 'google.com') -> bool:
    
    try:
      self.resolver.resolve(domain, 'A', tcp=True)
      return True
    except Exception:
      return False

  def reverse_lookup(self, ip_address: str) -> list[str] | dict[str, str]:
    
    try:
      nome = dns.reversename.from_address(ip_address)
      resposta = self.resolver.resolve(nome, 'PTR')
      return [r.to_text() for r in resposta]
    except Exception as e:
      return {'error': str(type(e).__name__), 'details': str(e)}

  def test_dnssec_support(self, domain: str = 'cloudflare.com') -> bool:
   
    try:
      self.resolver.use_edns(0, dns.flags.DO)
      resposta = self.resolver.resolve(domain, 'A')
      return bool(resposta.response.flags & dns.flags.AD)
    except Exception:
      return False
    finally:
      self.resolver.use_edns(False)