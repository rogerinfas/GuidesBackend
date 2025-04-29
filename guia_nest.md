# Guía Completa de NestJS desde Cero

<div align="center">
  <img src="https://nestjs.com/img/logo-small.svg" width="120" alt="Nest Logo" />
</div>

## 📋 Tabla de Contenidos

- [Introducción](#introducción)
- [Prerrequisitos](#prerrequisitos)
- [Instalación](#instalación)
- [Estructura del Proyecto](#estructura-del-proyecto)
- [Controladores](#controladores)
- [Proveedores](#proveedores)
- [Módulos](#módulos)
- [Middleware](#middleware)
- [Excepciones](#excepciones)
- [Pipes](#pipes)
- [Guards](#guards)
- [Interceptores](#interceptores)
- [Bases de Datos](#bases-de-datos)
- [Autenticación](#autenticación)
- [Validación](#validación)
- [Despliegue](#despliegue)
- [Mejores Prácticas](#mejores-prácticas)

## 🚀 Introducción

NestJS es un framework progresivo de Node.js para construir aplicaciones del lado del servidor eficientes, confiables y escalables. Está construido con TypeScript y combina elementos de la programación orientada a objetos (OOP), la programación funcional (FP) y la programación funcional reactiva (FRP).

NestJS se inspira en Angular, adoptando su arquitectura modular y proporcionando una estructura clara para organizar tu código.

## 🛠️ Prerrequisitos

Antes de comenzar con NestJS, asegúrate de tener instalado:

- Node.js (versión 16.x o superior)
- npm (normalmente viene con Node.js)
- TypeScript (conocimiento básico)

## ⚙️ Instalación

### 1. Instalar NestJS CLI

```bash
npm i -g @nestjs/cli
```

### 2. Crear un nuevo proyecto

```bash
nest new nombre-proyecto
```

Esto iniciará un asistente interactivo donde puedes elegir tu gestor de paquetes preferido (npm, yarn o pnpm).

### 3. Estructura inicial

Después de crear el proyecto, navega a la carpeta del proyecto y ejecuta:

```bash
cd nombre-proyecto
npm run start:dev
```

Tu aplicación estará disponible en `http://localhost:3000`.

## 📁 Estructura del Proyecto

```
src/
├── app.controller.spec.ts  # Pruebas para el controlador
├── app.controller.ts       # Controlador básico
├── app.module.ts           # Módulo raíz de la aplicación
├── app.service.ts          # Servicio básico
└── main.ts                 # Punto de entrada de la aplicación
```

## 🎮 Controladores

Los controladores son responsables de manejar las solicitudes HTTP entrantes y devolver respuestas al cliente.

### Crear un controlador

```bash
nest generate controller usuarios
# O la forma corta
nest g co usuarios
```

### Ejemplo de controlador básico

```typescript
import { Controller, Get, Post, Body, Param } from '@nestjs/common';
import { UsuariosService } from './usuarios.service';
import { CreateUsuarioDto } from './dto/create-usuario.dto';

@Controller('usuarios')
export class UsuariosController {
  constructor(private readonly usuariosService: UsuariosService) {}

  @Get()
  findAll() {
    return this.usuariosService.findAll();
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usuariosService.findOne(+id);
  }

  @Post()
  create(@Body() createUsuarioDto: CreateUsuarioDto) {
    return this.usuariosService.create(createUsuarioDto);
  }
}
```

## 🔧 Proveedores

Los proveedores son una parte fundamental de NestJS. Muchas clases básicas de NestJS pueden ser tratadas como proveedores: servicios, repositorios, factories, helpers, etc.

### Crear un servicio

```bash
nest generate service usuarios
# O la forma corta
nest g s usuarios
```

### Ejemplo de servicio básico

```typescript
import { Injectable } from '@nestjs/common';
import { CreateUsuarioDto } from './dto/create-usuario.dto';

@Injectable()
export class UsuariosService {
  private usuarios = [];

  findAll() {
    return this.usuarios;
  }

  findOne(id: number) {
    return this.usuarios.find(usuario => usuario.id === id);
  }

  create(createUsuarioDto: CreateUsuarioDto) {
    const nuevoUsuario = {
      id: this.usuarios.length + 1,
      ...createUsuarioDto,
    };
    this.usuarios.push(nuevoUsuario);
    return nuevoUsuario;
  }
}
```

## 📦 Módulos

Los módulos son clases anotadas con el decorador `@Module()`. Organizan la aplicación en componentes lógicos cohesivos.

### Crear un módulo

```bash
nest generate module usuarios
# O la forma corta
nest g mo usuarios
```

### Ejemplo de módulo

```typescript
import { Module } from '@nestjs/common';
import { UsuariosController } from './usuarios.controller';
import { UsuariosService } from './usuarios.service';

@Module({
  controllers: [UsuariosController],
  providers: [UsuariosService],
  exports: [UsuariosService], // Exporta el servicio para usarlo en otros módulos
})
export class UsuariosModule {}
```

## 🔄 Middleware

Los middleware son funciones que se ejecutan antes del manejador de ruta.

### Crear un middleware

```bash
nest generate middleware logger
# O la forma corta
nest g mi logger
```

### Ejemplo de middleware

```typescript
import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';

@Injectable()
export class LoggerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    console.log(`Solicitud a: ${req.path}`);
    next();
  }
}
```

### Aplicar middleware a un módulo

```typescript
import { Module, MiddlewareConsumer, RequestMethod } from '@nestjs/common';
import { LoggerMiddleware } from './common/middleware/logger.middleware';
import { UsuariosController } from './usuarios/usuarios.controller';

@Module({
  // ...
})
export class AppModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(LoggerMiddleware)
      .forRoutes(UsuariosController);
  }
}
```

## ⚠️ Excepciones

NestJS proporciona una capa de excepciones integrada para manejar errores de forma consistente.

### Ejemplos de excepciones incorporadas

```typescript
import { HttpException, HttpStatus, NotFoundException } from '@nestjs/common';

// Manera 1: Usando HttpException
throw new HttpException('Mensaje de error', HttpStatus.FORBIDDEN);

// Manera 2: Usando excepciones específicas
throw new NotFoundException('Usuario no encontrado');
```

### Filtro de excepciones personalizado

```typescript
import { ExceptionFilter, Catch, ArgumentsHost, HttpException } from '@nestjs/common';
import { Response } from 'express';

@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: HttpException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const status = exception.getStatus();

    response
      .status(status)
      .json({
        statusCode: status,
        timestamp: new Date().toISOString(),
        message: exception.message,
      });
  }
}
```

## 🧪 Pipes

Los pipes son utilizados para la transformación de datos y validación.

### Pipes incorporados

- `ValidationPipe`
- `ParseIntPipe`
- `ParseBoolPipe`
- `ParseArrayPipe`
- `ParseUUIDPipe`

### Ejemplo de uso de pipes

```typescript
import { Controller, Get, Param, ParseIntPipe } from '@nestjs/common';

@Controller('usuarios')
export class UsuariosController {
  @Get(':id')
  findOne(@Param('id', ParseIntPipe) id: number) {
    return `Este action retorna el usuario #${id}`;
  }
}
```

### Pipe personalizado

```typescript
import { PipeTransform, Injectable, ArgumentMetadata, BadRequestException } from '@nestjs/common';

@Injectable()
export class PositiveNumberPipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    const val = parseInt(value, 10);
    if (isNaN(val) || val <= 0) {
      throw new BadRequestException('El valor debe ser un número positivo');
    }
    return val;
  }
}
```

## 🔒 Guards

Los guards determinan si una solicitud será manejada por el controlador o no, principalmente para la autorización.

### Crear un guard

```bash
nest generate guard auth
# O la forma corta
nest g gu auth
```

### Ejemplo de guard

```typescript
import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest();
    // Aquí iría tu lógica de autenticación
    return true; // Si devuelve false, NestJS denegará la solicitud
  }
}
```

## 🔄 Interceptores

Los interceptores tienen capacidades útiles como:
- Agregar lógica adicional antes/después de la ejecución del método
- Transformar el resultado retornado
- Manejar errores
- Extender el comportamiento básico del método

### Crear un interceptor

```bash
nest generate interceptor transform
# O la forma corta
nest g in transform
```

### Ejemplo de interceptor

```typescript
import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

export interface Response<T> {
  data: T;
}

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, Response<T>> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<Response<T>> {
    return next.handle().pipe(map(data => ({ data })));
  }
}
```

## 💾 Bases de Datos

NestJS se integra fácilmente con varias bases de datos a través de TypeORM, Mongoose, Sequelize, Prisma, etc.

### Configurar TypeORM

1. Instalar las dependencias:

```bash
npm install --save @nestjs/typeorm typeorm mysql2
```

2. Configurar el módulo TypeORM:

```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsuariosModule } from './usuarios/usuarios.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: 'localhost',
      port: 3306,
      username: 'root',
      password: 'root',
      database: 'mibasededatos',
      entities: [__dirname + '/**/*.entity{.ts,.js}'],
      synchronize: true, // ¡NO usar synchronize en producción!
    }),
    UsuariosModule,
  ],
})
export class AppModule {}
```

### Crear una entidad

```typescript
import { Entity, Column, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
export class Usuario {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  nombre: string;

  @Column()
  email: string;

  @Column({ default: true })
  activo: boolean;
}
```

### Configurar el repositorio

```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsuariosController } from './usuarios.controller';
import { UsuariosService } from './usuarios.service';
import { Usuario } from './entities/usuario.entity';

@Module({
  imports: [TypeOrmModule.forFeature([Usuario])],
  controllers: [UsuariosController],
  providers: [UsuariosService],
})
export class UsuariosModule {}
```

### Usar el repositorio en el servicio

```typescript
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Usuario } from './entities/usuario.entity';
import { CreateUsuarioDto } from './dto/create-usuario.dto';

@Injectable()
export class UsuariosService {
  constructor(
    @InjectRepository(Usuario)
    private usuariosRepository: Repository<Usuario>,
  ) {}

  findAll(): Promise<Usuario[]> {
    return this.usuariosRepository.find();
  }

  findOne(id: number): Promise<Usuario> {
    return this.usuariosRepository.findOne({ where: { id } });
  }

  create(createUsuarioDto: CreateUsuarioDto): Promise<Usuario> {
    const usuario = new Usuario();
    Object.assign(usuario, createUsuarioDto);
    return this.usuariosRepository.save(usuario);
  }

  async remove(id: number): Promise<void> {
    await this.usuariosRepository.delete(id);
  }
}
```

## 🔐 Autenticación

NestJS proporciona herramientas para implementar autenticación basada en JWT, Passport, etc.

### Configurar autenticación JWT

1. Instalar dependencias:

```bash
npm install @nestjs/jwt @nestjs/passport passport passport-jwt passport-local
```

2. Crear un módulo de autenticación:

```typescript
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { UsuariosModule } from '../usuarios/usuarios.module';

@Module({
  imports: [
    UsuariosModule,
    PassportModule,
    JwtModule.register({
      secret: 'tu_secreto', // Utiliza variables de entorno para esto
      signOptions: { expiresIn: '60m' },
    }),
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
```

3. Implementar el servicio de autenticación:

```typescript
import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsuariosService } from '../usuarios/usuarios.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(
    private usuariosService: UsuariosService,
    private jwtService: JwtService,
  ) {}

  async validateUser(email: string, password: string): Promise<any> {
    const usuario = await this.usuariosService.findByEmail(email);
    if (usuario && await bcrypt.compare(password, usuario.password)) {
      const { password, ...result } = usuario;
      return result;
    }
    return null;
  }

  async login(usuario: any) {
    const payload = { email: usuario.email, sub: usuario.id };
    return {
      access_token: this.jwtService.sign(payload),
    };
  }
}
```

4. Crear estrategia JWT:

```typescript
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: 'tu_secreto', // Utiliza variables de entorno para esto
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, email: payload.email };
  }
}
```

## ✅ Validación

NestJS utiliza class-validator y class-transformer para validar datos entrantes.

1. Instalar dependencias:

```bash
npm install class-validator class-transformer
```

2. Crear un DTO con validaciones:

```typescript
import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class CreateUsuarioDto {
  @IsNotEmpty()
  @IsString()
  nombre: string;

  @IsEmail()
  email: string;

  @IsString()
  @MinLength(6)
  password: string;
}
```

3. Habilitar la validación en el módulo principal:

```typescript
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe());
  await app.listen(3000);
}
bootstrap();
```

## 🚀 Despliegue

Hay varias formas de desplegar una aplicación NestJS:

### 1. Despliegue tradicional

1. Construir la aplicación:

```bash
npm run build
```

2. Iniciar la aplicación:

```bash
node dist/main.js
```

### 2. Despliegue con Docker

1. Crear un `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

RUN npm run build

EXPOSE 3000

CMD ["node", "dist/main"]
```

2. Construir la imagen Docker:

```bash
docker build -t mi-aplicacion-nest .
```

3. Ejecutar el contenedor:

```bash
docker run -p 3000:3000 mi-aplicacion-nest
```

## 🏆 Mejores Prácticas

1. **Organización del código**: Sigue la estructura recomendada por NestJS.
2. **Validación**: Siempre valida los datos de entrada.
3. **Configuración**: Usa variables de entorno para las configuraciones.
4. **Logging**: Implementa un sistema de logging adecuado.
5. **Pruebas**: Escribe pruebas unitarias, de integración y e2e.
6. **Documentación**: Documenta tu API con Swagger.
7. **Seguridad**: Implementa seguridad adecuada (CORS, CSRF, etc.).
8. **Optimización**: Usa técnicas de optimización como caché, compresión, etc.

### Configuración de Swagger

1. Instalar dependencias:

```bash
npm install @nestjs/swagger swagger-ui-express
```

2. Configurar Swagger:

```typescript
import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder()
    .setTitle('API de Usuarios')
    .setDescription('API para gestionar usuarios')
    .setVersion('1.0')
    .addTag('usuarios')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  await app.listen(3000);
}
bootstrap();
```

---

## 📚 Recursos Adicionales

- [Documentación oficial de NestJS](https://docs.nestjs.com/)
- [Repositorio de NestJS en GitHub](https://github.com/nestjs/nest)
- [Ejemplos oficiales de NestJS](https://github.com/nestjs/nest/tree/master/sample)
- [Comunidad de NestJS en Discord](https://discord.gg/nestjs)

---

Esta guía cubre los conceptos básicos de NestJS para ayudarte a comenzar, pero hay mucho más que aprender. Consulta la documentación oficial para información más detallada y ejemplos avanzados.