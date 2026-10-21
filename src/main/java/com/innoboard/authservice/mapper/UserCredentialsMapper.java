package com.innoboard.authservice.mapper;

import com.innoboard.authservice.domain.UserCredentials;
import com.innoboard.authservice.dto.UserCredentialsResponse;
import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface UserCredentialsMapper {
    UserCredentialsResponse toResponse(UserCredentials entity);
}
