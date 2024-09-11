import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersService } from './users/users.service';
import { UsersModule } from './users/users.module';
import { PrismaModule } from './prisma/prisma.module';
import { APP_GUARD } from '@nestjs/core';
import { AtGuard } from './auth/common/guards';
import { JwtModule, JwtService } from '@nestjs/jwt';

@Module({
  imports: [AuthModule, UsersModule, PrismaModule],
  controllers: [AppController],
  providers: [AppService, UsersService, {provide: APP_GUARD, useClass: AtGuard}, {provide: JwtService, useClass: JwtModule}],
  
})
export class AppModule {}
