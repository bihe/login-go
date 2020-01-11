import { NgModule } from '@angular/core';
import { MatBadgeModule, MatCardModule, MatProgressSpinnerModule, MatSnackBarModule, MatTooltipModule } from '@angular/material';
// import { MatCardModule } from '@angular/material/card';
// import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { MatButtonModule } from '@angular/material/button';
import { MatChipsModule } from '@angular/material/chips';
import { AppComponent } from './components/app/app.component';
import { EditComponent } from './components/edit/edit.component';
import { FooterComponent } from './components/footer/footer.component';
import { HeaderComponent } from './components/header/header.component';
import { HomeComponent } from './components/home/home.component';
import { DateFormatPipe } from './shared/pipes/dateformat';
import { EllipsisPipe } from './shared/pipes/ellipsis';
import { ApiAppInfoService } from './shared/service/api.app.service';
import { ApiUserService } from './shared/service/api.sites.service';
import { ApplicationState } from './shared/service/application.state';


@NgModule({
  imports: [ MatProgressSpinnerModule, MatTooltipModule, MatSnackBarModule, MatButtonModule, MatChipsModule, MatCardModule, MatBadgeModule ],
  exports: [ MatProgressSpinnerModule, MatTooltipModule, MatSnackBarModule, MatButtonModule, MatChipsModule, MatCardModule, MatBadgeModule ],
})
export class AppMaterialModule { }

export const sharedConfig: NgModule = {
    bootstrap: [ AppComponent ],
    declarations: [
        AppComponent,
        HomeComponent,
        EditComponent,
        FooterComponent,
        HeaderComponent,
        EllipsisPipe,
        DateFormatPipe
    ],
    imports: [
        AppMaterialModule
    ],
    providers: [ ApplicationState, ApiAppInfoService, ApiUserService ],
    entryComponents: []
};
