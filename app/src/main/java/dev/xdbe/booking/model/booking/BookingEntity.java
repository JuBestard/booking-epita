package dev.xdbe.booking.model.booking;

import java.time.LocalDate;
import jakarta.persistence.*;

import dev.xdbe.booking.model.booking.CreditCardConverter;

@Entity
@Table(name = "BOOKING")
public class BookingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private LocalDate checkInDate;
    private LocalDate checkOutDate;
    private int nightStays;
    private String name;

    // Step 5: add annotation
    @Convert(converter = CreditCardConverter.class)
    private String creditCardNumber;

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public LocalDate getCheckInDate() {
        return checkInDate;
    }

    public void setCheckInDate(LocalDate checkInDate) {
        this.checkInDate = checkInDate;
    }

    public LocalDate getCheckOutDate() {
        return checkOutDate;
    }

    public void setCheckOutDate(LocalDate checkOutDate) {
        this.checkOutDate = checkOutDate;
    }

    public int getNightStays() {
        return nightStays;
    }

    public void setNightStays(int nightStays) {
        this.nightStays = nightStays;
    }
    
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCreditCardNumber() {
        return creditCardNumber;
    }

    public void setCreditCardNumber(String creditCardNumber) {
        this.creditCardNumber = creditCardNumber;
    }
}
