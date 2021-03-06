# ASP.NET CORE JWT ile Authentication

@settings {
  font-size: 10;
}

## Yüklü olan Nu-Get Solution
![resim](https://user-images.githubusercontent.com/76875926/178302011-ab65b689-dc6b-4772-a661-a7688bf8c192.png)



## İlgili Attribute'ler
<img src="https://user-images.githubusercontent.com/76875926/178302689-3e37cb7d-d034-417a-aefb-aa9a185518f5.png" width="500">

> Temel anlamda erişimi kısıtlamak için controller sınıfımıza "Authorize" attribute’sini eklemek yeterlidir.





<img src="https://user-images.githubusercontent.com/76875926/178303077-d3e70a23-e675-4a41-a9ee-bfd43b818cbf.png" width="500">

> Eğer erişimi kısıtlamak istemiyorsak "AllowAnonymous" attribute’sini kullanırız.

## Startup'da Gerekli Ayarların Yapılması
> ConfigureServices metoduna aşağıdaki gerekli başlangıç ayarları yapılır.

```c#
  services.AddAuthentication(x => 
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(x => 
            {
                x.RequireHttpsMetadata = false;
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_key)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                };
            });
```

> Configure metoduna aşağıdaki satır eklenir.
```c#
  app.UseAuthentication();
```

## Token Oluşturma İşlemi
> Aşağıdaki metot kullanıcının olup olmadığına bakıyor kullanıcı varsa token döndürüyor.
```c#
    public string Authenticate(string username, string password)
        {
            if(!_users.Any(m => m.Key == username && m.Value == password))
            {
                return null;
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(_key);
            var tokenDescription = new SecurityTokenDescriptor()
            {
                // Gövdemin
                Subject = new ClaimsIdentity(new Claim[] 
                { 
                    new Claim(ClaimTypes.Name, username)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescription);
            return tokenHandler.WriteToken(token);
        }
```
