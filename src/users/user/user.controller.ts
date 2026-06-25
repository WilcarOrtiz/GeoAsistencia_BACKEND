import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  ParseUUIDPipe,
  Query,
  UseGuards,
  UseInterceptors,
  BadRequestException,
  UploadedFile,
  HttpStatus,
  Res,
  InternalServerErrorException,
  Headers,
} from '@nestjs/common';
import { UserService } from './service/user.service';
import {
  ApiBody,
  ApiConsumes,
  ApiOkResponse,
  ApiOperation,
} from '@nestjs/swagger';

import * as DTO from './dto';
import {
  GetUser,
  PublicAccess,
  RequiredPermissions,
} from 'src/common/decorators';
import { PermissionsGuard } from 'src/common/guard';
import { RoleListItemDto } from 'src/access-control-module/roles/dto/roles-response.dto';
import type { ICurrentUser } from 'src/common/interface/current-user.interface';
import { toDto, toPaginatedDto } from 'src/common/utils/dto-mapper.util';
import { UserBulkService } from './service/user-bulk.service';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import express from 'express';
import { PERMISSIONS } from 'src/common/constants/permisos';

@Controller('user')
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly userBulkService: UserBulkService,
  ) {}

  @PublicAccess()
  @Get('is-active')
  @ApiOperation({
    summary: 'Verificar usuario activo',
    description:
      'Verificar si un usuario está activo, Recibe un correo y devuelve true o false si el usuario está activo.',
  })
  @ApiOkResponse({
    schema: { example: { isActive: true } },
  })
  async isActiveUser(@Query('email') email: string) {
    const isActive = await this.userService.isUserActiveByEmail(email);
    return { isActive };
  }

  @Patch('reset-devices')
  @RequiredPermissions(PERMISSIONS.RECUPERAR_PASSWORD)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Resetear dispositivos registrados',
  })
  @ApiOkResponse({
    description: 'UUIDs eliminados correctamente',
  })
  async resetDevices(@Body() dto: DTO.ResetDevicesDto) {
    return this.userService.resetDevices(dto.userIds);
  }

  @Post()
  @RequiredPermissions(PERMISSIONS.CREAR_USUARIO)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Registrar usuario',
    description:
      'Registra un usuario en Supabase Auth y registra su información base en la base de datos. Asigna los roles indicados.',
  })
  @ApiOkResponse({ type: DTO.UserResponseWithRolesDto })
  async create(@Body() dto: DTO.CreateUserDto) {
    return toDto(
      DTO.UserResponseWithRolesDto,
      await this.userService.createUser(dto),
    );
  }

  @Patch(':id/roles')
  @RequiredPermissions(PERMISSIONS.EDITAR_USUARIO)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Actualizar roles de un usuario',
    description: 'Reemplaza completamente los roles asignados a un usuario.',
  })
  @ApiOkResponse({ type: [RoleListItemDto] })
  async updateUserRoles(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() updateRolesUserDto: DTO.UpdateRolesUserDto,
  ) {
    return toDto(
      RoleListItemDto,
      await this.userService.updateRoles(id, updateRolesUserDto),
    );
  }

  @Patch(':id')
  @RequiredPermissions(PERMISSIONS.EDITAR_USUARIO)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Actualizar información básica del usuario',
    description:
      'Actualiza los datos base del usuario (nombres, apellidos, estado, etc.) utilizando su auth_id. No modifica roles ni credenciales de autenticación.',
  })
  @ApiOkResponse({ type: DTO.UserBaseResponseDto })
  async update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: DTO.UpdateUserDto,
  ) {
    return toDto(
      DTO.UserBaseResponseDto,
      await this.userService.update(id, dto),
    );
  }

  @Patch(':id/deactivate')
  @RequiredPermissions(PERMISSIONS.DESACTIVAR_USUARIO)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Desactivar usuario',
    description:
      'Marca el usuario como inactivo (is_active = false). No elimina registros ni credenciales.',
  })
  @ApiOkResponse({
    schema: {
      example: { is_active: false },
    },
  })
  async deactivate(@Param('id', ParseUUIDPipe) id: string) {
    return await this.userService.setStatus(id, false);
  }

  @Patch(':id/activate')
  @RequiredPermissions(PERMISSIONS.ACTIVAR_USUARIO)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Activar usuario',
    description:
      'Reactiva un usuario previamente desactivado (is_active = true). Valida que el usuario exista y que no esté activo previamente..',
  })
  @ApiOkResponse({
    schema: {
      example: { is_active: true },
    },
  })
  async activate(@Param('id', ParseUUIDPipe) id: string) {
    return await this.userService.setStatus(id, true);
  }

  @Get('me')
  @ApiOperation({
    summary: 'Obtener perfil detallado',
    description: `
  Retorna la información completa del usuario procesando la jerarquía de seguridad.
  
  **Lo que incluye esta respuesta:**
  * **Roles asignados:** Lista de roles vinculados al usuario.
  * **Permisos efectivos:** Cálculo de permisos únicos (evita duplicidad si varios roles comparten permisos).
  * **Menú de navegación:** Estructura dinámica basada en los permisos obtenidos.
  * **Nombre Completo:** Campo calculado que concatena nombre y apellidos.
  `,
  })
  @ApiOkResponse({ type: DTO.UserMeResponseDto })
  async getProfile(
    @GetUser() user: ICurrentUser,
    @Headers('x-device-id') deviceId?: string,
  ) {
    console.log('DEVICE ID:', deviceId);
    return await this.userService.getUserProfile(user, deviceId);
  }

  @Get(':id')
  @RequiredPermissions(PERMISSIONS.VER_USUARIOS)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Obtener un usuario',
  })
  @ApiOkResponse({ type: DTO.UserResponseWithRolesDto })
  async findOne(@Param('id', ParseUUIDPipe) id: string) {
    return toDto(
      DTO.UserResponseWithRolesDto,
      await this.userService.findOne(id),
    );
  }

  @Get()
  @RequiredPermissions(PERMISSIONS.VER_USUARIOS)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Listar usuarios',
    description: `
    Obtiene una lista paginada de usuarios con soporte para:.
    * **1:** Inclusión opcional de usuarios inactivos.
    * **2:** Filtro por rol.
    * **3:** Paginación (page, limit).
    `,
  })
  @ApiOkResponse({ type: DTO.PaginatedUserResponseDto })
  async findAll(
    @Query() findAllUsersDto: DTO.FindAllUsersDto,
  ): Promise<DTO.PaginatedUserResponseDto> {
    const result = await this.userService.findAll(findAllUsersDto);
    return toPaginatedDto(DTO.UserResponseWithRolesDto, result);
  }

  @RequiredPermissions(PERMISSIONS.DESCARGAR_PLANTILLA_USUARIOS)
  @UseGuards(PermissionsGuard)
  @Get('bulk/template')
  async downloadTemplate(@Res() res: express.Response) {
    try {
      const buffer = await this.userBulkService.generateTemplate();

      res.set({
        'Content-Type':
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="plantilla_usuarios.xlsx"`,
        'Content-Length': buffer.length,
      });

      return res.status(HttpStatus.OK).send(buffer);
    } catch {
      throw new InternalServerErrorException('No se pudo generar la plantilla');
    }
  }

  @Post('bulk/import')
  @RequiredPermissions(PERMISSIONS.IMPORTAR_USUARIOS)
  @UseGuards(PermissionsGuard)
  @ApiOperation({
    summary: 'Importar usuarios masivamente desde un archivo Excel',
    description:
      'Recibe un archivo .xlsx (con la misma estructura de la plantilla), ' +
      'valida cada fila y crea los usuarios. ' +
      'Devuelve cuántos se crearon y cuáles fallaron con el motivo.',
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        file: { type: 'string', format: 'binary' },
      },
    },
  })
  @ApiOkResponse({
    schema: {
      example: {
        created: 5,
        failed: [
          { row: 4, ID: '1066865142', errors: ['Email ya está en uso'] },
        ],
      },
    },
  })
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
      limits: { fileSize: 5 * 1024 * 1024 },
      fileFilter: (_, file, cb) => {
        const allowed = [
          'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'application/vnd.ms-excel',
        ];
        if (!allowed.includes(file.mimetype)) {
          return cb(
            new BadRequestException('Solo se permiten archivos .xlsx o .xls'),
            false,
          );
        }
        cb(null, true);
      },
    }),
  )
  async bulkImport(@UploadedFile() file: Express.Multer.File) {
    if (!file) throw new BadRequestException('No se recibió ningún archivo');
    return this.userBulkService.bulkImport(file.buffer);
  }
}
