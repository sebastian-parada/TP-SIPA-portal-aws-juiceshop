# Portal de acceso a Juice Shop en AWS

Configuración del entorno del TP de Seguridad Informática y Principios de Auditoría (FCE-UBA, 2do período 2026). Juice Shop corre en una instancia EC2 y un portal en AWS Lambda permite que cada integrante habilite su propia IP con un código personal.

Este README cubre solo lo que se agregó sobre el instructivo. La cuenta AWS, el 2FA, el presupuesto de 0 USD, la instancia EC2 con Ubuntu, la conexión SSH, la instalación de Docker y la descarga de Juice Shop se hicieron siguiendo los instructivos de la cátedra y no se repiten acá.

## Contenido

```
.
├── README.md              este archivo
├── crear_codigos.py       genera los códigos y guarda los hashes en SSM, se ejecuta en CloudShell.
├── lambda_function.py     código de la función Lambda del portal
└── resumen-servidor.pdf   archivos y componentes del servidor, estructura y decisiones.
```

## Valores que se reemplazan

Estos valores salen de la propia cuenta de AWS y no se publican en el repositorio.

| Marcador | Qué es |
| --- | --- |
| `<ID_CUENTA>` | ID de la cuenta AWS (12 dígitos) |
| `<ID_SG_PORTAL>` | ID del Security Group `juice-portal-access` (`sg-...`) |
| `<ID_INSTANCIA>` | ID de la instancia EC2 |
| `<IP_PUBLICA>` | IP pública de la instancia |
| `<TU_DOMINIO>` | Dominio propio |

Región usada: `us-east-1` (N. Virginia).

## 1. Juice Shop en segundo plano

Se reemplaza el `docker run` del instructivo por esta versión, para que siga corriendo si se cierra el SSH o se reinicia el servidor:

```bash
docker run -d --restart unless-stopped --name juice-shop -p 3000:3000 bkimminich/juice-shop
```

Verificación:

```bash
docker ps
curl -I http://localhost:3000
```

Tiene que figurar `juice-shop` en estado `Up` y la segunda orden tiene que devolver `200 OK`. Juice Shop tarda unos 20 a 30 segundos en responder después de arrancar.

Si el contenedor existe pero está detenido: `docker start juice-shop`.

## 2. Subdominio

Se creó un registro en el editor de zona DNS del dominio (no en la sección de subdominios del hosting, que apunta a una carpeta y no a otro servidor).

| Tipo | Nombre | Valor | TTL |
| --- | --- | --- | --- |
| A | `juice` | `<IP_PUBLICA>` | 1000 |

Verificación desde PowerShell:

```powershell
nslookup juice.<TU_DOMINIO>
```

Tiene que devolver la IP pública de la instancia. Juice Shop se abre con `http://juice.<TU_DOMINIO>:3000` (siempre `http`, no `https`).

## 3. Security Group del portal

1. EC2 > Security Groups > Crear grupo de seguridad.
2. Nombre: `juice-portal-access`.
3. Descripción: `IPs de integrantes gestionadas por el portal`.
4. VPC: la misma de la instancia.
5. Reglas de entrada: ninguna.
6. Crear y anotar el ID (`<ID_SG_PORTAL>`).
7. EC2 > Instancias > seleccionar la instancia > Acciones > Seguridad > Cambiar grupos de seguridad.
8. Agregar `juice-portal-access` y dejar también el grupo original (el del SSH).
9. Guardar.

Las reglas de los dos grupos se suman. El portal solo va a tener permisos sobre `juice-portal-access`.

## 4. Política IAM

IAM > Políticas > Crear política > JSON. Nombre: `juice-portal-policy`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ManageOnlyPortalSG",
      "Effect": "Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Resource": "arn:aws:ec2:us-east-1:<ID_CUENTA>:security-group/<ID_SG_PORTAL>"
    },
    {
      "Sid": "ReadSecurityGroupRules",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadPortalCodes",
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:us-east-1:<ID_CUENTA>:parameter/juice-portal/*"
    }
  ]
}
```

## 5. Rol de la Lambda

1. IAM > Roles > Crear rol.
2. Entidad de confianza: Servicio de AWS, caso de uso Lambda.
3. Adjuntar `juice-portal-policy` y `AWSLambdaBasicExecutionRole`.
4. Nombre: `juice-portal-role`.

No se agrega ninguna otra política.

## 6. Códigos individuales

Los códigos se generan en AWS CloudShell para que no pasen por chats, mails ni archivos.

1. Entrar a la consola en la región `us-east-1` y abrir CloudShell (ícono `>_` de la barra superior).
2. Editar la lista `NOMBRES` de `crear_codigos.py` con los integrantes.
3. Acciones > Cargar archivos > subir `crear_codigos.py`.
4. Ejecutar:

```bash
python3 crear_codigos.py
```

5. El script guarda los hashes en el parámetro SecureString `/juice-portal/codes` y muestra los códigos una sola vez.
6. Copiar cada código y enviarlo por privado a su dueño.
7. Limpiar la pantalla:

```bash
clear
```

Características: 20 caracteres aleatorios de un alfabeto de 57 (unos 117 bits), hash scrypt (N=16384, r=8, p=1) con sal de 16 bytes. Volver a ejecutar el script cambia los códigos de todos.

## 7. Función Lambda

1. Lambda > Crear función > Crear desde cero.
2. Nombre: `juice-portal`. Runtime: el Python 3.x más nuevo disponible. Arquitectura: x86_64.
3. Permisos: usar un rol existente, `juice-portal-role`.
4. En la pestaña Código, reemplazar el contenido de `lambda_function.py` por el del archivo del repositorio y tocar Deploy.
5. Configuración > General: tiempo de espera 10 segundos, memoria 256 MB.
6. Configuración > Variables de entorno:

| Clave | Valor |
| --- | --- |
| `SG_ID` | `<ID_SG_PORTAL>` |
| `PARAM_NAME` | `/juice-portal/codes` |
| `PORT` | `3000` |
| `REDIRECT_URL` | `http://juice.<TU_DOMINIO>:3000/` |
| `MAX_IPS` | `2` |
| `MAX_RULES` | `40` |

No se configuró simultaneidad reservada: la cuenta tiene un límite de 10 ejecuciones y AWS exige dejar 10 sin reservar.

## 8. Function URL

1. Configuración > URL de la función > Crear URL de función.
2. Tipo de autenticación: NONE.
3. CORS: desactivado.
4. Guardar y copiar la URL (`https://<id>.lambda-url.us-east-1.on.aws/`).

Esa es la URL que se comparte con el equipo.

## 9. Prueba

1. Abrir la URL del portal desde una red distinta a la de la computadora (por ejemplo, datos móviles).
2. Ingresar nombre y código.
3. Tiene que mostrar "Acceso habilitado" y redirigir a Juice Shop.
4. Verificar que apareció una regla `portal:<Nombre>:<fecha>` en el Security Group `juice-portal-access`.

Si algo falla, los eventos quedan en Lambda > Monitoreo > Ver registros en CloudWatch:

| Evento | Significado |
| --- | --- |
| `ACCESO_OK` | Se habilitó una IP |
| `LOGIN_FAIL` | Nombre o código incorrecto |
| `LOGIN_ERROR` | Error al leer el pedido o el parámetro de SSM |
| `GRANT_ERROR` | No se pudo agregar la regla |
| `IPV6` | La persona llegó por IPv6 |
| `IP_INVALIDA` | La IP de origen no es pública |

## 10. Operación

**Una persona no puede entrar por IPv6.** Pedirle que abra `https://api.ipify.org`, que muestra su IPv4, y agregar a mano en `juice-portal-access` una regla TCP 3000 con origen `<esa IP>/32` y descripción `manual:<Nombre>`. El portal no toca las reglas que no empiezan con `portal:`.

**Revocar a una persona.** En SSM > Parameter Store, editar el valor de `/juice-portal/codes` y borrar su entrada; el cambio rige en unos 5 minutos. Después, borrar sus reglas `portal:<Nombre>:...` del Security Group.

**Cambiar todos los códigos.** Volver a ejecutar `crear_codigos.py` en CloudShell.

**La IP del servidor cambia** solo si se detiene y vuelve a iniciar la instancia. En ese caso hay que editar el registro A del subdominio.

## 11. Cierre del TP

1. Detener la instancia en EC2.
2. Borrar el registro A de `juice`.
3. Borrar la función Lambda `juice-portal`, el rol `juice-portal-role` y la política `juice-portal-policy`.
4. Borrar el parámetro `/juice-portal/codes` de SSM.
5. Borrar el Security Group `juice-portal-access` y revisar que no queden volúmenes ni instancias sin usar.
6. Revisar Billing para confirmar que no hay cargos.

## Uso y atribución

Este material es de Sebastián Parada. Podés usar, copiar y modificar el código y la documentación, también en otros trabajos, siempre que cites al autor (Sebastián Parada) y enlaces a este repositorio. Se ofrece tal cual, sin garantía de ningún tipo.
